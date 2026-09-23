// Snowflake Cortex wire-format transforms, shared by the provider fetch, the
// OAuth plugin fetch, and the proxied path in resolveSDK. Cortex speaks an
// OpenAI-compatible dialect with quirks: `max_tokens` must be sent as
// `max_completion_tokens`, "conversation complete" 400s mean clean stop, and
// empty `role` strings in SSE must read as assistant.

export function transformRequestBody(body: BodyInit | null | undefined): BodyInit | null | undefined {
  if (body && typeof body === "string") {
    try {
      const parsed: unknown = JSON.parse(body)
      // Guard the `in` check: valid JSON primitives (null, "123", '"x"')
      // would otherwise throw TypeError instead of passing through.
      if (typeof parsed === "object" && parsed !== null && "max_tokens" in parsed) {
        const record = parsed as Record<string, unknown>
        record.max_completion_tokens = record.max_tokens
        delete record.max_tokens
        return JSON.stringify(record)
      }
    } catch {}
  }
  return body
}

export async function normalizeResponse(response: Response): Promise<Response> {
  if (!response.ok && response.status === 400) {
    try {
      const errorData = await response.clone().json()
      const errorMessage = String(errorData.message || errorData.error || "")
      if (errorMessage.toLowerCase().includes("conversation complete")) {
        return new Response(
          JSON.stringify({
            choices: [{ finish_reason: "stop", message: { content: "", role: "assistant" } }],
          }),
          { status: 200, headers: new Headers({ "content-type": "application/json" }) },
        )
      }
    } catch {}
  }

  if (response.body && response.headers.get("content-type")?.includes("text/event-stream")) {
    const reader = response.body.getReader()
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()
    const stream = new ReadableStream({
      async pull(ctrl) {
        const { done, value } = await reader.read()
        if (done) {
          ctrl.close()
          return
        }
        const text = decoder.decode(value, { stream: true })
        ctrl.enqueue(encoder.encode(text.replace(/"role"\s*:\s*""/g, '"role":"assistant"')))
      },
      cancel() {
        reader.cancel()
      },
    })
    return new Response(stream, { headers: response.headers, status: response.status })
  }

  return response
}

// Namespace object (not `export * as … from "./snowflake-transform"`): a
// self-referential barrel can resolve to an uninitialized namespace under
// some loaders. Existing `import { SnowflakeTransform }` sites are unaffected.
export const SnowflakeTransform = {
  transformRequestBody,
  normalizeResponse,
}
