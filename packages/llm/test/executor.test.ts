import { describe, expect } from "bun:test"
import { Effect, Fiber, Layer, Random, Ref } from "effect"
import * as TestClock from "effect/testing/TestClock"
import { Headers, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http"
import { LLM, LLMError } from "../src"
import { LLMClient, RequestExecutor } from "../src/route"
import * as OpenAIChat from "../src/protocols/openai-chat"
import { dynamicResponse } from "./lib/http"
import { deltaChunk } from "./lib/openai-chunks"
import { sseRaw } from "./lib/sse"
import { it } from "./lib/effect"

const request = HttpClientRequest.post("https://provider.test/v1/chat?api_key=secret&key=secret&debug=1").pipe(
  HttpClientRequest.setHeaders(Headers.fromInput({ authorization: "Bearer secret", "x-safe": "visible" })),
)

const secretRequest = HttpClientRequest.post("https://provider.test/v1/chat?api_key=query-secret-123&debug=1").pipe(
  HttpClientRequest.setHeaders(Headers.fromInput({ authorization: "Bearer header-secret-456" })),
)

const responsesLayer = (responses: ReadonlyArray<Response>) =>
  RequestExecutor.layer.pipe(
    Layer.provide(
      Layer.unwrap(
        Effect.gen(function* () {
          const cursor = yield* Ref.make(0)
          return Layer.succeed(
            HttpClient.HttpClient,
            HttpClient.make((request) =>
              Effect.gen(function* () {
                const index = yield* Ref.getAndUpdate(cursor, (value) => value + 1)
                return HttpClientResponse.fromWeb(request, responses[index] ?? responses[responses.length - 1])
              }),
            ),
          )
        }),
      ),
    ),
  )

const countedResponsesLayer = (attempts: Ref.Ref<number>, responses: ReadonlyArray<Response>) =>
  RequestExecutor.layer.pipe(
    Layer.provide(
      Layer.unwrap(
        Effect.gen(function* () {
          const cursor = yield* Ref.make(0)
          return Layer.succeed(
            HttpClient.HttpClient,
            HttpClient.make((request) =>
              Effect.gen(function* () {
                yield* Ref.update(attempts, (value) => value + 1)
                const index = yield* Ref.getAndUpdate(cursor, (value) => value + 1)
                return HttpClientResponse.fromWeb(request, responses[index] ?? responses[responses.length - 1])
              }),
            ),
          )
        }),
      ),
    ),
  )

const randomMidpoint = {
  nextDoubleUnsafe: () => 0.5,
  nextIntUnsafe: () => 0,
}

const expectLLMError = (error: unknown) => {
  expect(error).toBeInstanceOf(LLMError)
  if (!(error instanceof LLMError)) throw new Error("expected LLMError")
  return error
}

const errorHttp = (error: LLMError) => ("http" in error.reason ? error.reason.http : undefined)

describe("RequestExecutor", () => {
  it.effect("classifies context overflow responses", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "InvalidRequest", classification: "context-overflow" })
    }).pipe(
      Effect.provide(
        responsesLayer([
          new Response('{"error":{"code":"context_length_exceeded","message":"prompt too long"}}', {
            status: 400,
          }),
        ]),
      ),
    ),
  )

  it.effect("does not classify generic HTTP 413 payload errors as context overflow", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "InvalidRequest" })
      expect("classification" in error.reason ? error.reason.classification : undefined).toBeUndefined()
    }).pipe(Effect.provide(responsesLayer([new Response("request too large", { status: 413 })]))),
  )

  it.effect("does not classify ordinary invalid requests as context overflow", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "InvalidRequest" })
      expect("classification" in error.reason ? error.reason.classification : undefined).toBeUndefined()
    }).pipe(Effect.provide(responsesLayer([new Response("invalid parameter", { status: 400 })]))),
  )

  it.effect("returns redacted diagnostics for retryable rate limits", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error).toMatchObject({
        retryable: true,
        retryAfterMs: 0,
        reason: {
          _tag: "RateLimit",
          rateLimit: { retryAfterMs: 0 },
          http: {
            requestId: "req_123",
            request: {
              method: "POST",
              url: "https://provider.test/v1/chat?api_key=%3Credacted%3E&key=%3Credacted%3E&debug=1",
              headers: { authorization: "<redacted>", "x-safe": "visible" },
            },
            response: {
              status: 429,
              headers: {
                "retry-after-ms": "0",
                "x-request-id": "req_123",
                "x-api-key": "<redacted>",
              },
            },
          },
        },
      })
      expect(errorHttp(error)?.body).toBe("rate limited")
    }).pipe(
      Effect.provide(
        responsesLayer(
          Array.from(
            { length: 3 },
            () =>
              new Response("rate limited", {
                status: 429,
                headers: { "retry-after-ms": "0", "x-request-id": "req_123", "x-api-key": "secret" },
              }),
          ),
        ),
      ),
    ),
  )

  it.effect("honors current redacted header names in diagnostics", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(errorHttp(error)?.request.headers["x-safe"]).toBe("<redacted>")
      expect(errorHttp(error)?.response?.headers["x-safe"]).toBe("<redacted>")
    }).pipe(
      Effect.provide(responsesLayer([new Response("bad", { status: 400, headers: { "x-safe": "response-secret" } })])),
      Effect.provideService(Headers.CurrentRedactedNames, ["x-safe"]),
    ),
  )

  it.effect("extracts OpenAI-style rate-limit diagnostics", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "RateLimit" })
      expect(error.reason._tag === "RateLimit" ? error.reason.rateLimit : undefined).toEqual({
        retryAfterMs: 0,
        limit: { requests: "500", tokens: "30000" },
        remaining: { requests: "499", tokens: "29900" },
        reset: { requests: "1s", tokens: "10s" },
      })
    }).pipe(
      Effect.provide(
        responsesLayer(
          Array.from(
            { length: 3 },
            () =>
              new Response("rate limited", {
                status: 429,
                headers: {
                  "retry-after-ms": "0",
                  "x-ratelimit-limit-requests": "500",
                  "x-ratelimit-limit-tokens": "30000",
                  "x-ratelimit-remaining-requests": "499",
                  "x-ratelimit-remaining-tokens": "29900",
                  "x-ratelimit-reset-requests": "1s",
                  "x-ratelimit-reset-tokens": "10s",
                },
              }),
          ),
        ),
      ),
    ),
  )

  it.effect("extracts Anthropic-style rate-limit diagnostics", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "ProviderInternal" })
      expect(errorHttp(error)?.rateLimit).toEqual({
        retryAfterMs: 0,
        limit: { requests: "100", "input-tokens": "10000" },
        remaining: { requests: "12", "input-tokens": "9000" },
        reset: { requests: "2026-05-06T12:00:00Z", "input-tokens": "2026-05-06T12:00:10Z" },
      })
    }).pipe(
      Effect.provide(
        responsesLayer(
          Array.from(
            { length: 3 },
            () =>
              new Response("overloaded", {
                status: 529,
                headers: {
                  "retry-after-ms": "0",
                  "anthropic-ratelimit-requests-limit": "100",
                  "anthropic-ratelimit-requests-remaining": "12",
                  "anthropic-ratelimit-requests-reset": "2026-05-06T12:00:00Z",
                  "anthropic-ratelimit-input-tokens-limit": "10000",
                  "anthropic-ratelimit-input-tokens-remaining": "9000",
                  "anthropic-ratelimit-input-tokens-reset": "2026-05-06T12:00:10Z",
                },
              }),
          ),
        ),
      ),
    ),
  )

  it.effect("retries retryable status responses before returning the stream", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const response = yield* executor.execute(request)

      expect(response.status).toBe(200)
      expect(yield* response.text).toBe("ok")
    }).pipe(
      Effect.provide(
        responsesLayer([
          new Response("busy", { status: 503, headers: { "retry-after-ms": "0" } }),
          new Response("ok", { status: 200 }),
        ]),
      ),
    ),
  )

  it.effect("marks 504 and 529 status responses retryable", () =>
    Effect.gen(function* () {
      const failWith = (status: number) =>
        Effect.gen(function* () {
          const executor = yield* RequestExecutor.Service
          const error = yield* executor.execute(request).pipe(Effect.flip)

          expectLLMError(error)
          expect(error.reason).toMatchObject({ _tag: "ProviderInternal", status })
          expect(error.retryable).toBe(true)
        }).pipe(
          Effect.provide(
            responsesLayer(
              Array.from(
                { length: 3 },
                () =>
                  new Response("retry", {
                    status,
                    headers: { "retry-after-ms": "0" },
                  }),
              ),
            ),
          ),
        )

      yield* failWith(504)
      yield* failWith(529)
    }),
  )

  it.effect("does not retry non-retryable status responses and truncates large bodies", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "Authentication" })
      expect(error.retryable).toBe(false)
      expect(errorHttp(error)?.bodyTruncated).toBe(true)
      expect(errorHttp(error)?.body).toHaveLength(16_384)
    }).pipe(
      Effect.provide(
        responsesLayer([
          new Response("x".repeat(20_000), { status: 401 }),
          new Response("should not retry", { status: 200 }),
        ]),
      ),
    ),
  )

  it.effect("redacts common secret fields in response bodies", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(request).pipe(Effect.flip)

      expectLLMError(error)
      expect(errorHttp(error)?.body).toContain('"key":"<redacted>"')
      expect(errorHttp(error)?.body).toContain("api_key=<redacted>")
      expect(errorHttp(error)?.body).not.toContain("body-secret")
      expect(errorHttp(error)?.body).not.toContain("query-secret")
    }).pipe(
      Effect.provide(
        responsesLayer([
          new Response('{"error":{"message":"bad","key":"body-secret","detail":"api_key=query-secret"}}', {
            status: 400,
          }),
        ]),
      ),
    ),
  )

  it.effect("redacts echoed request secret values in response bodies", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor.execute(secretRequest).pipe(Effect.flip)

      expectLLMError(error)
      expect(errorHttp(error)?.body).toContain("provider echoed <redacted>")
      expect(errorHttp(error)?.body).toContain("authorization <redacted>")
      expect(errorHttp(error)?.body).not.toContain("query-secret-123")
      expect(errorHttp(error)?.body).not.toContain("header-secret-456")
    }).pipe(
      Effect.provide(
        responsesLayer([
          new Response("provider echoed query-secret-123 and authorization header-secret-456", { status: 400 }),
        ]),
      ),
    ),
  )

  it.effect("honors Retry-After delta seconds before retrying", () =>
    Effect.gen(function* () {
      const attempts = yield* Ref.make(0)
      return yield* Effect.gen(function* () {
        const executor = yield* RequestExecutor.Service
        const fiber = yield* executor.execute(request).pipe(Effect.forkChild)

        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(1)

        yield* TestClock.adjust(1_999)
        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(1)

        yield* TestClock.adjust(1)
        const response = yield* Fiber.join(fiber)

        expect(response.status).toBe(200)
        expect(yield* Ref.get(attempts)).toBe(2)
      }).pipe(
        Effect.provide(
          countedResponsesLayer(attempts, [
            new Response("busy", { status: 503, headers: { "retry-after": "2" } }),
            new Response("ok", { status: 200 }),
          ]),
        ),
      )
    }),
  )

  it.effect("uses exponential jittered delay when retry-after is absent", () =>
    Effect.gen(function* () {
      const attempts = yield* Ref.make(0)
      return yield* Effect.gen(function* () {
        const executor = yield* RequestExecutor.Service
        const fiber = yield* executor.execute(request).pipe(Effect.flip, Effect.forkChild)

        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(1)

        yield* TestClock.adjust(499)
        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(1)

        yield* TestClock.adjust(1)
        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(2)

        yield* TestClock.adjust(999)
        yield* Effect.yieldNow
        expect(yield* Ref.get(attempts)).toBe(2)

        yield* TestClock.adjust(1)
        const error = yield* Fiber.join(fiber)

        expectLLMError(error)
        expect(error.reason).toMatchObject({ _tag: "ProviderInternal" })
        expect(yield* Ref.get(attempts)).toBe(3)
      }).pipe(
        Effect.provide(
          countedResponsesLayer(attempts, [
            new Response("busy", { status: 503 }),
            new Response("still busy", { status: 503 }),
            new Response("done retrying", { status: 503 }),
          ]),
        ),
      )
    }).pipe(Effect.provideService(Random.Random, randomMidpoint)),
  )

  it.effect("routes http targets through an http proxy in absolute form", () =>
    Effect.gen(function* () {
      const seen: string[] = []
      const server = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        fetch: (req) => {
          seen.push(`${req.method} ${req.url}`)
          return new Response("ok", { status: 200 })
        },
      })
      try {
        const executor = yield* RequestExecutor.Service
        const response = yield* executor.execute(
          HttpClientRequest.get(`http://127.0.0.1:${server.port}/llm`),
          { proxy: `http://127.0.0.1:${server.port}/` },
        )
        expect(response.status).toBe(200)
        expect(seen).toHaveLength(1)
        expect(seen[0]).toBe(`GET http://127.0.0.1:${server.port}/llm`)
      } finally {
        server.stop()
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("fails fast when the proxy demands auth", () =>
    Effect.gen(function* () {
      const server = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        fetch: () =>
          new Response("proxy auth required", {
            status: 407,
            headers: { "proxy-authenticate": 'Basic realm="proxy"' },
          }),
      })
      try {
        const executor = yield* RequestExecutor.Service
        const error = yield* executor
          .execute(HttpClientRequest.get(`http://127.0.0.1:${server.port}/llm`), {
            proxy: `http://127.0.0.1:${server.port}/`,
          })
          .pipe(Effect.flip)
        expectLLMError(error)
        expect(error.reason).toMatchObject({ _tag: "UnknownProvider", status: 407 })
      } finally {
        server.stop()
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("refuses to send loopback targets to remote proxies", () =>
    Effect.gen(function* () {
      const executor = yield* RequestExecutor.Service
      const error = yield* executor
        .execute(HttpClientRequest.get("http://127.0.0.1:9/llm"), { proxy: "http://proxy.corp:8080/" })
        .pipe(Effect.flip)
      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "Transport", kind: "proxy" })
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("never sends cleartext to an https: proxy", () =>
    Effect.gen(function* () {
      const { createServer } = yield* Effect.promise(() => import("node:net"))
      // Plaintext stub: records the first byte of every connection, then
      // destroys it so the client handshake fails fast instead of hanging.
      const firstBytes: number[] = []
      const server = createServer((socket) => {
        socket.once("data", (chunk: Buffer) => {
          firstBytes.push(chunk[0] as number)
          socket.destroy()
        })
      })
      const port: number = yield* Effect.promise(
        () =>
          new Promise<number>((resolve) => {
            server.listen(0, "127.0.0.1", () => {
              const address = server.address()
              resolve(typeof address === "object" && address ? address.port : 0)
            })
          }),
      )
      try {
        const executor = yield* RequestExecutor.Service
        const error = yield* executor
          .execute(HttpClientRequest.get(`http://127.0.0.1:${port}/llm`), {
            proxy: `https://127.0.0.1:${port}/`,
          })
          .pipe(Effect.flip)
        expectLLMError(error)
        expect(error.reason).toMatchObject({ _tag: "Transport", kind: "proxy" })
        expect(firstBytes.length).toBeGreaterThan(0)
        // Every attempt must start with a TLS ClientHello (0x16), never a
        // plaintext CONNECT ("C") carrying Proxy-Authorization in cleartext.
        for (const first of firstBytes) expect(first).toBe(0x16)
      } finally {
        yield* Effect.promise(() => new Promise<void>((resolve) => server.close(() => resolve())))
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("does not truncate split Content-Length bodies through a proxy", () =>
    Effect.gen(function* () {
      const body = "x".repeat(60) + "y".repeat(40)
      const { createServer } = yield* Effect.promise(() => import("node:net"))
      const server = createServer((socket) => {
        let head = Buffer.alloc(0)
        const onData = (chunk: Buffer) => {
          head = Buffer.concat([head, chunk])
          if (head.indexOf("\r\n\r\n") === -1) return
          socket.off("data", onData)
          // Split the 100-byte body as 60 + 40 across two writes to catch
          // double-decrement framing bugs.
          socket.write(`HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n${body.slice(0, 60)}`)
          setTimeout(() => {
            socket.write(body.slice(60))
            socket.end()
          }, 10)
        }
        socket.on("data", onData)
      })
      const port: number = yield* Effect.promise(
        () =>
          new Promise<number>((resolve) => {
            server.listen(0, "127.0.0.1", () => {
              const address = server.address()
              resolve(typeof address === "object" && address ? address.port : 0)
            })
          }),
      )
      try {
        const executor = yield* RequestExecutor.Service
        const response = yield* executor.execute(HttpClientRequest.get(`http://127.0.0.1:${port}/llm`), {
          proxy: `http://127.0.0.1:${port}/`,
        })
        expect(response.status).toBe(200)
        expect(yield* response.text).toBe(body)
      } finally {
        yield* Effect.promise(() => new Promise<void>((resolve) => server.close(() => resolve())))
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("streams close-delimited bodies through a proxy until close", () =>
    Effect.gen(function* () {
      const body = "close-delimited-body"
      const { createServer } = yield* Effect.promise(() => import("node:net"))
      const server = createServer((socket) => {
        let head = Buffer.alloc(0)
        const onData = (chunk: Buffer) => {
          head = Buffer.concat([head, chunk])
          if (head.indexOf("\r\n\r\n") === -1) return
          socket.off("data", onData)
          socket.write(`HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n${body}`)
          socket.end()
        }
        socket.on("data", onData)
      })
      const port: number = yield* Effect.promise(
        () =>
          new Promise<number>((resolve) => {
            server.listen(0, "127.0.0.1", () => {
              const address = server.address()
              resolve(typeof address === "object" && address ? address.port : 0)
            })
          }),
      )
      try {
        const executor = yield* RequestExecutor.Service
        const response = yield* executor.execute(HttpClientRequest.get(`http://127.0.0.1:${port}/llm`), {
          proxy: `http://127.0.0.1:${port}/`,
        })
        expect(response.status).toBe(200)
        expect(yield* response.text).toBe(body)
      } finally {
        yield* Effect.promise(() => new Promise<void>((resolve) => server.close(() => resolve())))
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("surfaces truncated Content-Length bodies through a proxy as errors", () =>
    Effect.gen(function* () {
      const { createServer } = yield* Effect.promise(() => import("node:net"))
      const server = createServer((socket) => {
        let head = Buffer.alloc(0)
        const onData = (chunk: Buffer) => {
          head = Buffer.concat([head, chunk])
          if (head.indexOf("\r\n\r\n") === -1) return
          socket.off("data", onData)
          // Declare 100 bytes but close after 60: truncation must error,
          // not silently succeed with the prefix.
          socket.write(`HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n${"x".repeat(60)}`)
          socket.end()
        }
        socket.on("data", onData)
      })
      const port: number = yield* Effect.promise(
        () =>
          new Promise<number>((resolve) => {
            server.listen(0, "127.0.0.1", () => {
              const address = server.address()
              resolve(typeof address === "object" && address ? address.port : 0)
            })
          }),
      )
      try {
        const executor = yield* RequestExecutor.Service
        const response = yield* executor.execute(HttpClientRequest.get(`http://127.0.0.1:${port}/llm`), {
          proxy: `http://127.0.0.1:${port}/`,
        })
        expect(response.status).toBe(200)
        const error = yield* response.text.pipe(Effect.flip)
        // The body error surfaces wrapped as a decode failure — the point is
        // it fails instead of silently succeeding with the 60-byte prefix.
        expect(String(error)).toMatch(/decode|closed|completed/i)
      } finally {
        yield* Effect.promise(() => new Promise<void>((resolve) => server.close(() => resolve())))
      }
    }).pipe(Effect.provide(RequestExecutor.fetchLayer)),
  )

  it.effect("does not retry after a successful response reaches stream parsing", () =>
    Effect.gen(function* () {
      const attempts = yield* Ref.make(0)
      const model = OpenAIChat.route
        .with({ endpoint: { baseURL: "https://api.openai.test/v1" } })
        .model({ id: "gpt-4o-mini" })
      const error = yield* LLMClient.generate(LLM.request({ model, prompt: "Say hello." })).pipe(
        Effect.provide(
          dynamicResponse((input) =>
            Ref.update(attempts, (value) => value + 1).pipe(
              Effect.as(
                input.respond(
                  sseRaw(
                    `data: ${JSON.stringify(deltaChunk({ role: "assistant", content: "Hello" }))}`,
                    "data: not-json",
                  ),
                  { headers: { "content-type": "text/event-stream" } },
                ),
              ),
            ),
          ),
        ),
        Effect.flip,
      )

      expectLLMError(error)
      expect(error.reason).toMatchObject({ _tag: "InvalidProviderOutput" })
      expect(yield* Ref.get(attempts)).toBe(1)
    }),
  )
})
