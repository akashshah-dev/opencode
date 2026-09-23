import { afterEach, expect } from "bun:test"
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import { streamText } from "ai"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { Effect } from "effect"
import { ProviderV2 } from "@opencode-ai/core/provider"
import { ModelV2 } from "@opencode-ai/core/model"
import { disposeAllInstances, provideTmpdirInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"
import { testProviderConfig } from "../lib/test-provider"
import { Env } from "@/env"
import { Plugin } from "@/plugin"
import { Provider } from "@/provider/provider"
import { ProxyFetch } from "@/proxy/fetch"
import type { ConfigProxyV1 } from "@opencode-ai/core/v1/config/proxy"

afterEach(async () => {
  await disposeAllInstances()
})

const it = testEffect(
  LayerNode.compile(LayerNode.group([Provider.node, Env.node, Plugin.node, CrossSpawnSpawner.node])),
)

interface ProxyHit {
  url: string
  authorization: string | undefined
}

interface ProxyServer {
  server: Server
  url: string
  hits: ProxyHit[]
  directHits: number
}

// Minimal forward proxy for plain-HTTP targets. Records absolute-form request
// URLs, optionally enforces basic auth, and answers with a canned SSE body so
// the test can prove traffic flowed through the proxy (the target must see 0
// direct hits). A separate target server answers direct requests.
function proxyServer(options?: { username?: string; password?: string }) {
  return Effect.promise(() => {
    const hits: ProxyHit[] = []
    const state = { directHits: 0 }
    const sse = `data: {"choices":[{"delta":{"role":"assistant"}}]}\n\ndata: {"choices":[{"delta":{"content":"via-proxy"}}]}\n\ndata: {"choices":[{"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n`
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      // Origin-form URLs arrived direct; absolute-form URLs came via the proxy.
      // (undici normalizes loopback absolute-form to origin-form, so the fake
      // LLM lives under /llm and any absolute-form request counts as proxied.)
      if (req.url?.startsWith("/")) {
        state.directHits++
        res.writeHead(200, { "content-type": "text/event-stream" })
        res.end(sse.replaceAll("via-proxy", "direct"))
        return
      }
      hits.push({ url: req.url ?? "", authorization: req.headers["proxy-authorization"] as string | undefined })
      if (options?.username) {
        const expected = `Basic ${Buffer.from(`${options.username}:${options.password}`).toString("base64")}`
        if (req.headers["proxy-authorization"] !== expected) {
          res.writeHead(407, { "proxy-authenticate": 'Basic realm="proxy"' })
          res.end("proxy auth required")
          return
        }
      }
      res.writeHead(200, { "content-type": "text/event-stream" })
      res.end(sse)
    })
    return new Promise<ProxyServer>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const address = server.address()
        if (!address || typeof address === "string") throw new Error("proxy failed to listen")
        resolve({
          server,
          url: `http://127.0.0.1:${address.port}`,
          hits,
          get directHits() {
            return state.directHits
          },
        })
      })
    })
  })
}

function complete(prompt: string, selection?: { proxyID?: string; config?: ConfigProxyV1.Info }) {
  return Effect.gen(function* () {
    const provider = yield* Provider.Service
    const model = yield* provider.getModel(ProviderV2.ID.make("test"), ModelV2.ID.make("test-model"))
    const result = streamText({
      model: yield* provider.getLanguage(model, selection ? { proxy: selection } : undefined),
      onError() {},
      messages: [{ role: "user", content: prompt }],
    })
    return yield* Effect.promise(() => result.text)
  })
}

it.live("routes session proxy requests through an HTTP proxy", () =>
  Effect.gen(function* () {
    const proxy = yield* Effect.acquireRelease(proxyServer(), (p) =>
      Effect.sync(() => p.server.close()),
    )
    yield* provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const text = yield* complete("hello", {
            proxyID: "corp",
            config: { proxies: { corp: { name: "Corp", type: "http", url: proxy.url } } },
          })
          expect(text).toBe("via-proxy")
          expect(proxy.hits).toHaveLength(1)
          expect(proxy.hits[0]!.url).toStartWith("http://127.0.0.1:")
          expect(proxy.directHits).toBe(0)
        }),
      { config: testProviderConfig(`${proxy.url}/llm`) },
    )
  }),
)

it.live("reuses pooled proxy sockets across sequential requests", () =>
  Effect.gen(function* () {
    const proxy = yield* Effect.acquireRelease(proxyServer(), (p) =>
      Effect.sync(() => p.server.close()),
    )
    yield* provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const selection = {
            proxyID: "corp",
            config: { proxies: { corp: { name: "Corp", type: "http" as const, url: proxy.url } } },
          }
          // The second request reuses the pooled keep-alive socket: pooled
          // reuse after partial consumption would read the previous body tail
          // as the next status line and fail.
          expect(yield* complete("one", selection)).toBe("via-proxy")
          expect(yield* complete("two", selection)).toBe("via-proxy")
          expect(proxy.hits).toHaveLength(2)
          expect(proxy.directHits).toBe(0)
        }),
      { config: testProviderConfig(`${proxy.url}/llm`) },
    )
  }),
)

it.live("sends proxy basic auth from username and passwordEnv", () =>
  Effect.gen(function* () {
    const proxy = yield* Effect.acquireRelease(proxyServer({ username: "bot", password: "s3cret" }), (p) =>
      Effect.sync(() => p.server.close()),
    )
    yield* provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          process.env.PROXY_FETCH_TEST_PASS = "s3cret"
          try {
            const text = yield* complete("hello", {
              proxyID: "corp",
              config: {
                proxies: {
                  corp: { name: "Corp", type: "http", url: proxy.url, username: "bot", passwordEnv: "PROXY_FETCH_TEST_PASS" },
                },
              },
            })
            expect(text).toBe("via-proxy")
            expect(proxy.hits).toHaveLength(1)
            expect(proxy.hits[0]!.authorization).toBe(`Basic ${Buffer.from("bot:s3cret").toString("base64")}`)
          } finally {
            delete process.env.PROXY_FETCH_TEST_PASS
          }
        }),
      { config: testProviderConfig(`${proxy.url}/llm`) },
    )
  }),
)

it.live("fails fast on proxy auth rejection without silent fallback", () =>
  Effect.gen(function* () {
    const proxy = yield* Effect.acquireRelease(proxyServer({ username: "bot", password: "s3cret" }), (p) =>
      Effect.sync(() => p.server.close()),
    )
    yield* provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          // A 407 from the proxy surfaces through streamText as a stream
          // error, not a rejected text promise. Assert the failure is a 407
          // (not a silent direct fallback) via the low-level fetch path.
          const response = yield* Effect.promise(() =>
            ProxyFetch.fetch(
              ProxyFetch.createPool(),
              {
                proxyID: "corp",
                config: { proxies: { corp: { name: "Corp", type: "http", url: proxy.url } } },
              },
              `${proxy.url}/llm/chat/completions`,
              { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
            )!,
          )
          expect(response?.status).toBe(407)
          expect(yield* Effect.promise(() => response!.text())).toMatch(/proxy auth/i)
          expect(proxy.hits).toHaveLength(1)
          expect(proxy.directHits).toBe(0)
        }),
      { config: testProviderConfig(`${proxy.url}/llm`) },
    )
  }),
)

it.live("direct selection bypasses the configured proxy", () =>
  Effect.gen(function* () {
    const proxy = yield* Effect.acquireRelease(proxyServer(), (p) =>
      Effect.sync(() => p.server.close()),
    )
    yield* provideTmpdirInstance(
      () =>
        Effect.gen(function* () {
          const text = yield* complete("hello", {
            proxyID: "direct",
            config: { proxies: { corp: { name: "Corp", type: "http", url: proxy.url } } },
          })
          expect(text).toBe("direct")
          expect(proxy.hits).toHaveLength(0)
          expect(proxy.directHits).toBe(1)
        }),
      { config: testProviderConfig(`${proxy.url}/llm`) },
    )
  }),
)
