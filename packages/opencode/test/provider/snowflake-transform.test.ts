import { expect, test } from "bun:test"
import { SnowflakeTransform } from "@/provider/snowflake-transform"

test("rewrites max_tokens to max_completion_tokens", () => {
  expect(SnowflakeTransform.transformRequestBody(JSON.stringify({ max_tokens: 10, other: 1 }))).toBe(
    JSON.stringify({ other: 1, max_completion_tokens: 10 }),
  )
})

test("leaves non-JSON and other bodies alone", () => {
  expect(SnowflakeTransform.transformRequestBody(undefined)).toBeUndefined()
  expect(SnowflakeTransform.transformRequestBody(null)).toBeNull()
  expect(SnowflakeTransform.transformRequestBody("not-json")).toBe("not-json")
  expect(SnowflakeTransform.transformRequestBody(JSON.stringify({ stream: true }))).toBe(
    JSON.stringify({ stream: true }),
  )
})

test("passes through valid JSON primitives without throwing", () => {
  // The `in` guard must not throw TypeError on parsed null/number/string.
  for (const primitive of ["null", "123", '"max_tokens"', "[1,2]"]) {
    expect(SnowflakeTransform.transformRequestBody(primitive)).toBe(primitive)
  }
})

test("normalizes conversation-complete 400s into clean stops", async () => {
  const response = await SnowflakeTransform.normalizeResponse(
    new Response(JSON.stringify({ message: "Conversation complete" }), { status: 400 }),
  )
  expect(response.status).toBe(200)
  expect(await response.json()).toEqual({
    choices: [{ finish_reason: "stop", message: { content: "", role: "assistant" } }],
  })
})

test("passes through unrelated errors and bodies", async () => {
  const error = await SnowflakeTransform.normalizeResponse(new Response("nope", { status: 500 }))
  expect(error.status).toBe(500)
  expect(await error.text()).toBe("nope")

  const sse = await SnowflakeTransform.normalizeResponse(
    new Response('data: {"role":""}\n\n', { headers: { "content-type": "text/event-stream" } }),
  )
  expect(await sse.text()).toBe('data: {"role":"assistant"}\n\n')
})
