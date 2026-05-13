import { zValidator } from "@hono/zod-validator";
import type { Context } from "hono";
import { Hono } from "hono";
import { proxy } from "hono/proxy";
import { getConfig } from "../config";
import type { PlaceholderContext } from "../masking/context";
import { codexExtractor } from "../masking/extractors/codex";
import { unmaskResponse as unmaskPIIResponse } from "../pii/mask";
import { type CodexProviderResult, callCodex, getCodexInfo } from "../providers/codex/client";
import { createCodexUnmaskingStream } from "../providers/codex/stream-transformer";
import {
  type CodexResponsesRequest,
  CodexResponsesRequestSchema,
  type CodexResponsesResponse,
} from "../providers/codex/types";
import { unmaskSecretsResponse } from "../secrets/mask";
import { logRequest } from "../services/logger";
import { detectPII, maskPII, type PIIDetectResult } from "../services/pii";
import { processSecretsRequest, type SecretsProcessResult } from "../services/secrets";
import {
  createLogData,
  errorFormats,
  handleProviderError,
  setBlockedHeaders,
  setResponseHeaders,
  toPIIHeaderData,
  toPIILogData,
  toSecretsHeaderData,
  toSecretsLogData,
} from "./utils";

export const codexRoutes = new Hono();

/**
 * POST /responses
 *
 * Inspected Codex Responses route. This mirrors the OpenAI/Anthropic protected
 * endpoints: detect secrets/PII, mask before upstream, unmask streamed response,
 * and log the request in the dashboard.
 */
codexRoutes.post(
  "/responses",
  zValidator("json", CodexResponsesRequestSchema, (result, c) => {
    if (!result.success) {
      return c.json(
        errorFormats.openai.error(
          `Invalid request body: ${result.error.message}`,
          "invalid_request_error",
        ),
        400,
      );
    }
  }),
  async (c) => {
    const startTime = Date.now();
    let request = c.req.valid("json") as CodexResponsesRequest;
    const config = getConfig();

    const secretsResult = processSecretsRequest(request, config.secrets_detection, codexExtractor);
    if (secretsResult.blocked) {
      return respondBlocked(c, request, secretsResult, startTime);
    }
    if (secretsResult.masked) {
      request = secretsResult.request;
    }

    let piiResult: PIIDetectResult;
    if (!config.pii_detection.enabled) {
      piiResult = {
        detection: {
          hasPII: false,
          spanEntities: [],
          allEntities: [],
          scanTimeMs: 0,
          language: config.pii_detection.fallback_language,
          languageFallback: false,
        },
        hasPII: false,
      };
    } else {
      try {
        piiResult = await detectPII(request, codexExtractor);
      } catch (error) {
        console.error("PII detection error:", error);
        return respondDetectionError(c, request, startTime);
      }
    }

    const piiMasked =
      config.mode === "mask" ? maskPII(request, piiResult.detection, codexExtractor) : undefined;

    return sendToCodex(c, request, {
      request: piiMasked?.request ?? request,
      piiResult,
      piiMaskingContext: piiMasked?.maskingContext,
      secretsResult,
      startTime,
      headers: getForwardHeaders(c),
    });
  },
);

/**
 * Wildcard pass-through proxy for /models and any future Codex endpoints that do
 * not carry prompt content.
 */
codexRoutes.all("/*", (c) => {
  const config = getConfig();
  const { baseUrl } = getCodexInfo(config.providers.codex);
  const normalizedBaseUrl = baseUrl.replace(/\/$/, "");
  const path = c.req.path.replace(/^\/codex/, "");
  const query = c.req.url.includes("?") ? c.req.url.slice(c.req.url.indexOf("?")) : "";

  return proxy(`${normalizedBaseUrl}${path}${query}`, {
    ...c.req,
    headers: {
      ...c.req.header(),
      "X-Forwarded-Host": c.req.header("host"),
      host: undefined,
    },
  });
});

interface CodexOptions {
  request: CodexResponsesRequest;
  piiResult: PIIDetectResult;
  piiMaskingContext?: PlaceholderContext;
  secretsResult: SecretsProcessResult<CodexResponsesRequest>;
  startTime: number;
  headers: Record<string, string>;
}

function getForwardHeaders(c: Context): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(c.req.header())) {
    const lower = key.toLowerCase();
    if (lower === "host" || lower === "content-length" || lower === "content-type") continue;
    headers[key] = value;
  }
  headers["X-Forwarded-Host"] = c.req.header("host") || "";
  return headers;
}

function formatCodexForLog(request: CodexResponsesRequest): string | undefined {
  const spans = codexExtractor.extractTexts(request).filter((span) => span.role !== "system");
  if (spans.length === 0) return undefined;

  return spans
    .map((span) => `[${span.role || "unknown"} ${span.path}] ${span.text}`)
    .join("\n")
    .slice(0, 20000);
}

function respondBlocked(
  c: Context,
  body: CodexResponsesRequest,
  secretsResult: SecretsProcessResult<CodexResponsesRequest>,
  startTime: number,
) {
  const secretTypes = secretsResult.blockedTypes ?? [];

  setBlockedHeaders(c, secretTypes);

  logRequest(
    createLogData({
      provider: "codex",
      model: body.model || "unknown",
      startTime,
      secrets: { detected: true, types: secretTypes, masked: false },
      statusCode: 400,
      errorMessage: secretsResult.blockedReason,
    }),
    c.req.header("User-Agent") || null,
  );

  return c.json(
    errorFormats.openai.error(
      `Request blocked: detected secret material (${secretTypes.join(",")}). Remove secrets and retry.`,
      "invalid_request_error",
      "secrets_detected",
    ),
    400,
  );
}

function respondDetectionError(c: Context, body: CodexResponsesRequest, startTime: number) {
  logRequest(
    createLogData({
      provider: "codex",
      model: body.model || "unknown",
      startTime,
      statusCode: 503,
      errorMessage: "Detection service unavailable",
    }),
    c.req.header("User-Agent") || null,
  );

  return c.json(
    errorFormats.openai.error(
      "Detection service unavailable",
      "server_error",
      "service_unavailable",
    ),
    503,
  );
}

async function sendToCodex(c: Context, originalRequest: CodexResponsesRequest, opts: CodexOptions) {
  const config = getConfig();
  const { request, piiResult, piiMaskingContext, secretsResult, startTime, headers } = opts;
  const maskedContent =
    piiResult.hasPII || secretsResult.masked ? formatCodexForLog(request) : undefined;

  setResponseHeaders(
    c,
    config.mode,
    "codex",
    toPIIHeaderData(piiResult),
    toSecretsHeaderData(secretsResult),
  );

  try {
    const result = await callCodex(request, config.providers.codex, headers);

    logRequest(
      createLogData({
        provider: "codex",
        model: result.model || originalRequest.model || "unknown",
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
      }),
      c.req.header("User-Agent") || null,
    );

    if (result.isStreaming) {
      return respondStreaming(
        c,
        result,
        piiMaskingContext,
        secretsResult.maskingContext,
        config.masking,
      );
    }

    return respondJson(
      c,
      result.response,
      piiMaskingContext,
      secretsResult.maskingContext,
      config.masking,
    );
  } catch (error) {
    return handleProviderError(
      c,
      error,
      {
        provider: "codex",
        model: originalRequest.model || "unknown",
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
        userAgent: c.req.header("User-Agent") || null,
      },
      (msg) => errorFormats.openai.error(msg, "server_error", "upstream_error"),
    );
  }
}

function respondStreaming(
  c: Context,
  result: CodexProviderResult & { isStreaming: true },
  piiContext?: PlaceholderContext,
  secretsContext?: PlaceholderContext,
  maskingConfig = getConfig().masking,
) {
  c.header("Content-Type", "text/event-stream");
  c.header("Cache-Control", "no-cache");
  c.header("Connection", "keep-alive");

  if (piiContext || secretsContext) {
    return c.body(
      createCodexUnmaskingStream(result.response, piiContext, maskingConfig, secretsContext),
    );
  }

  return c.body(result.response);
}

function respondJson(
  c: Context,
  response: CodexResponsesResponse,
  piiContext?: PlaceholderContext,
  secretsContext?: PlaceholderContext,
  maskingConfig = getConfig().masking,
) {
  let result = response;

  if (piiContext) {
    result = unmaskPIIResponse(result, piiContext, maskingConfig, codexExtractor);
  }
  if (secretsContext) {
    result = unmaskSecretsResponse(result, secretsContext, codexExtractor);
  }

  return c.json(result);
}
