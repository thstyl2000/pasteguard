import { z } from "zod";

export const CodexResponsesRequestSchema = z
  .object({
    model: z.string().optional(),
    instructions: z.string().optional(),
    input: z.unknown().optional(),
    stream: z.boolean().optional(),
  })
  .passthrough();

export type CodexResponsesRequest = z.infer<typeof CodexResponsesRequestSchema>;
export type CodexResponsesResponse = Record<string, unknown>;
