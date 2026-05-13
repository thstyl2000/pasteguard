/**
 * Codex provider metadata.
 *
 * Codex ChatGPT-login traffic uses chatgpt.com/backend-api/codex, not the public
 * OpenAI API base URL.
 */

import type { CodexProviderConfig } from "../../config";
import { getConfig } from "../../config";
import { ProviderError } from "../errors";
import type { CodexResponsesRequest, CodexResponsesResponse } from "./types";

export type CodexProviderResult =
  | {
      isStreaming: true;
      response: ReadableStream<Uint8Array>;
      model: string;
    }
  | {
      isStreaming: false;
      response: CodexResponsesResponse;
      model: string;
    };

export async function callCodex(
  request: CodexResponsesRequest,
  config: CodexProviderConfig,
  headers: Record<string, string>,
): Promise<CodexProviderResult> {
  const model = request.model || "unknown";
  const endpoint = `${config.base_url.replace(/\/$/, "")}/responses`;
  const timeoutMs = getConfig().server.request_timeout * 1000;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
    signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
  });

  if (!response.ok) {
    throw new ProviderError(response.status, response.statusText, await response.text());
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("text/event-stream") || request.stream === true) {
    if (!response.body) {
      throw new Error("No response body for streaming request");
    }
    return { response: response.body, isStreaming: true, model };
  }

  return { response: await response.json(), isStreaming: false, model };
}

export function getCodexInfo(config: CodexProviderConfig): { baseUrl: string } {
  return {
    baseUrl: config.base_url,
  };
}
