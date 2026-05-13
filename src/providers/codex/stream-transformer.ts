import type { MaskingConfig } from "../../config";
import type { PlaceholderContext } from "../../masking/context";
import { flushMaskingBuffer, unmaskStreamChunk } from "../../pii/mask";

export function createCodexUnmaskingStream(
  stream: ReadableStream<Uint8Array>,
  piiContext: PlaceholderContext | undefined,
  maskingConfig: MaskingConfig,
  secretsContext?: PlaceholderContext,
): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let piiBuffer = "";
  let secretsBuffer = "";

  return new ReadableStream({
    async start(controller) {
      const reader = stream.getReader();

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          let output = decoder.decode(value, { stream: true });

          if (piiContext) {
            const result = unmaskStreamChunk(piiBuffer, output, piiContext, maskingConfig);
            piiBuffer = result.remainingBuffer;
            output = result.output;
          }

          if (secretsContext) {
            const result = unmaskStreamChunk(secretsBuffer, output, secretsContext, maskingConfig);
            secretsBuffer = result.remainingBuffer;
            output = result.output;
          }

          if (output) {
            controller.enqueue(encoder.encode(output));
          }
        }

        let finalOutput = "";
        if (piiContext && piiBuffer) {
          finalOutput += flushMaskingBuffer(piiBuffer, piiContext, maskingConfig);
        }
        if (secretsContext && secretsBuffer) {
          finalOutput += flushMaskingBuffer(secretsBuffer, secretsContext, maskingConfig);
        }
        if (finalOutput) {
          controller.enqueue(encoder.encode(finalOutput));
        }

        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
  });
}
