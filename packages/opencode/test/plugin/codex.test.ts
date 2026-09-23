import { beforeEach, describe, expect, test } from "bun:test"
import { createServer, type IncomingMessage } from "node:http"
import { type AddressInfo } from "node:net"
import { WebSocketServer } from "ws"
import {
  CodexAuthPlugin,
  lastSeenProxyID,
  parseJwtClaims,
  extractAccountIdFromClaims,
  extractAccountId,
  extractResidency,
  renderOAuthError,
  resetProxyConfigCache,
  resolveSessionProxy,
  type IdTokenClaims,
} from "../../src/plugin/openai/codex"

function createTestJwt(payload: object): string {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url")
  return `${header}.${body}.sig`
}

describe("plugin.codex", () => {
  test("escapes provider errors in callback HTML", () => {
    const error = `</div><script>alert("xss" & 'more')</script>`
    const html = renderOAuthError(error)

    expect(html).toContain("&lt;/div&gt;&lt;script&gt;alert(&quot;xss&quot; &amp; &#39;more&#39;)&lt;/script&gt;")
    expect(html).not.toContain(error)
  })

  describe("parseJwtClaims", () => {
    test("parses valid JWT with claims", () => {
      const payload = { email: "test@example.com", chatgpt_account_id: "acc-123" }
      const jwt = createTestJwt(payload)
      const claims = parseJwtClaims(jwt)
      expect(claims).toEqual(payload)
    })

    test("returns undefined for JWT with less than 3 parts", () => {
      expect(parseJwtClaims("invalid")).toBeUndefined()
      expect(parseJwtClaims("only.two")).toBeUndefined()
    })

    test("returns undefined for invalid base64", () => {
      expect(parseJwtClaims("a.!!!invalid!!!.b")).toBeUndefined()
    })

    test("returns undefined for invalid JSON payload", () => {
      const header = Buffer.from("{}").toString("base64url")
      const invalidJson = Buffer.from("not json").toString("base64url")
      expect(parseJwtClaims(`${header}.${invalidJson}.sig`)).toBeUndefined()
    })
  })

  describe("extractAccountIdFromClaims", () => {
    test("extracts chatgpt_account_id from root", () => {
      const claims: IdTokenClaims = { chatgpt_account_id: "acc-root" }
      expect(extractAccountIdFromClaims(claims)).toBe("acc-root")
    })

    test("extracts chatgpt_account_id from nested https://api.openai.com/auth", () => {
      const claims: IdTokenClaims = {
        "https://api.openai.com/auth": { chatgpt_account_id: "acc-nested" },
      }
      expect(extractAccountIdFromClaims(claims)).toBe("acc-nested")
    })

    test("prefers root over nested", () => {
      const claims: IdTokenClaims = {
        chatgpt_account_id: "acc-root",
        "https://api.openai.com/auth": { chatgpt_account_id: "acc-nested" },
      }
      expect(extractAccountIdFromClaims(claims)).toBe("acc-root")
    })

    test("extracts from organizations array as fallback", () => {
      const claims: IdTokenClaims = {
        organizations: [{ id: "org-123" }, { id: "org-456" }],
      }
      expect(extractAccountIdFromClaims(claims)).toBe("org-123")
    })

    test("returns undefined when no accountId found", () => {
      const claims: IdTokenClaims = { email: "test@example.com" }
      expect(extractAccountIdFromClaims(claims)).toBeUndefined()
    })
  })

  describe("extractAccountId", () => {
    test("extracts from id_token first", () => {
      const idToken = createTestJwt({ chatgpt_account_id: "from-id-token" })
      const accessToken = createTestJwt({ chatgpt_account_id: "from-access-token" })
      expect(
        extractAccountId({
          id_token: idToken,
          access_token: accessToken,
          refresh_token: "rt",
        }),
      ).toBe("from-id-token")
    })

    test("falls back to access_token when id_token has no accountId", () => {
      const idToken = createTestJwt({ email: "test@example.com" })
      const accessToken = createTestJwt({
        "https://api.openai.com/auth": { chatgpt_account_id: "from-access" },
      })
      expect(
        extractAccountId({
          id_token: idToken,
          access_token: accessToken,
          refresh_token: "rt",
        }),
      ).toBe("from-access")
    })

    test("returns undefined when no tokens have accountId", () => {
      const token = createTestJwt({ email: "test@example.com" })
      expect(
        extractAccountId({
          id_token: token,
          access_token: token,
          refresh_token: "rt",
        }),
      ).toBeUndefined()
    })

    test("handles missing id_token", () => {
      const accessToken = createTestJwt({ chatgpt_account_id: "acc-123" })
      expect(
        extractAccountId({
          id_token: "",
          access_token: accessToken,
          refresh_token: "rt",
        }),
      ).toBe("acc-123")
    })
  })

  describe("extractResidency", () => {
    test("extracts compute residency from the namespaced auth claims", () => {
      expect(
        extractResidency(
          createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "eu" },
          }),
        ),
      ).toBe("eu")
    })

    test("falls back to a root compute residency claim", () => {
      expect(extractResidency(createTestJwt({ chatgpt_compute_residency: "us" }))).toBe("us")
    })

    test("supports compute residency values without maintaining a region list", () => {
      expect(
        extractResidency(
          createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "ae" },
          }),
        ),
      ).toBe("ae")
      expect(
        extractResidency(
          createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "future-region_1" },
          }),
        ),
      ).toBe("future-region_1")
    })

    test("ignores unconstrained and data residency values", () => {
      expect(
        extractResidency(
          createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "no_constraint" },
          }),
        ),
      ).toBeUndefined()
      expect(
        extractResidency(
          createTestJwt({
            "https://api.openai.com/auth": { chatgpt_data_residency: "gb" },
          }),
        ),
      ).toBeUndefined()
      expect(extractResidency(createTestJwt({ chatgpt_compute_residency: "" }))).toBeUndefined()
      expect(extractResidency("not-a-jwt")).toBeUndefined()
    })

    test("prefers a namespaced unconstrained value over a root residency", () => {
      expect(
        extractResidency(
          createTestJwt({
            chatgpt_compute_residency: "eu",
            "https://api.openai.com/auth": { chatgpt_compute_residency: "no_constraint" },
          }),
        ),
      ).toBeUndefined()
    })
  })

  test("installs websocket transport only when experimental websockets are enabled", async () => {
    const disabled = await CodexAuthPlugin({} as never)
    const enabled = await CodexAuthPlugin({} as never, { experimentalWebSockets: true })

    const disabledOptions = await disabled.auth!.loader!(
      async () => ({ type: "api", key: "sk-test" }) as never,
      {} as never,
    )
    const enabledOptions = await enabled.auth!.loader!(
      async () => ({ type: "api", key: "sk-test" }) as never,
      {} as never,
    )

    expect(disabledOptions.fetch).toBeUndefined()
    expect(enabledOptions.fetch).toBeFunction()
    await enabled.dispose?.()
  })

  test("sends token residency only to the ChatGPT Codex backend", async () => {
    const requests: Array<{ path: string; residency: string | null }> = []
    using server = Bun.serve({
      port: 0,
      fetch(request) {
        requests.push({
          path: new URL(request.url).pathname,
          residency: request.headers.get("x-openai-internal-codex-residency"),
        })
        return new Response("{}")
      },
    })
    const hooks = await CodexAuthPlugin({} as never, {
      codexApiEndpoint: new URL("/backend-api/codex/responses", server.url).toString(),
    })
    const loaded = await hooks.auth!.loader!(
      async () =>
        ({
          type: "oauth",
          refresh: "refresh",
          access: createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "eu" },
          }),
          expires: Date.now() + 60_000,
        }) as never,
      {} as never,
    )

    await loaded.fetch!("https://api.openai.com/v1/responses")
    await loaded.fetch!(new URL("/other", server.url))

    expect(requests).toEqual([
      { path: "/backend-api/codex/responses", residency: "eu" },
      { path: "/other", residency: null },
    ])
  })

  test("sends token residency through the WebSocket transport", async () => {
    await using server = await createCodexWebSocketServer()
    const hooks = await CodexAuthPlugin({} as never, {
      codexApiEndpoint: server.url,
      experimentalWebSockets: true,
    })
    const loaded = await hooks.auth!.loader!(
      async () =>
        ({
          type: "oauth",
          refresh: "refresh",
          access: createTestJwt({
            "https://api.openai.com/auth": { chatgpt_compute_residency: "eu" },
          }),
          expires: Date.now() + 60_000,
        }) as never,
      {} as never,
    )

    const response = await loaded.fetch!("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { "session-id": "session-1" },
      body: JSON.stringify({ stream: true, input: "hi" }),
    })

    expect(await response.text()).toContain("data: [DONE]")
    expect(server.headers()?.["x-openai-internal-codex-residency"]).toBe("eu")
    await hooks.dispose?.()
  })

  test("evicts pooled websockets only when the session proxy changes", async () => {
    let connections = 0
    const http = createServer()
    const wss = new WebSocketServer({ server: http })
    wss.on("connection", (socket) => {
      connections += 1
      // `on`, not `once`: pooled sockets serve several sequential requests.
      socket.on("message", () => {
        socket.send(JSON.stringify({ type: "response.completed", response: { id: "resp" } }))
      })
    })
    await new Promise<void>((resolve, reject) => {
      http.once("error", reject)
      http.listen(0, "127.0.0.1", resolve)
    })
    const address = http.address() as AddressInfo
    const url = `http://127.0.0.1:${address.port}/backend-api/codex/responses`
    try {
      const hooks = await CodexAuthPlugin({} as never, {
        codexApiEndpoint: url,
        experimentalWebSockets: true,
      })
      const loaded = await hooks.auth!.loader!(
        async () => ({ type: "oauth", refresh: "r", access: "a", expires: Date.now() + 60_000 }) as never,
        {} as never,
      )
      const post = () =>
        loaded.fetch!(url, {
          method: "POST",
          headers: { "session-id": "session-1" },
          body: JSON.stringify({ stream: true, input: "hi" }),
        })
      const updated = (proxyID: string | undefined) =>
        hooks.event!({
          event: { type: "session.updated", properties: { info: { id: "session-1", proxyID } } },
        } as never)

      expect(await (await post()).text()).toContain("data: [DONE]")
      expect(connections).toBe(1)
      // Routine updates with an unchanged choice preserve the pooled socket…
      await updated(undefined)
      expect(await (await post()).text()).toContain("data: [DONE]")
      expect(connections).toBe(1)
      await updated(undefined)
      expect(await (await post()).text()).toContain("data: [DONE]")
      expect(connections).toBe(1)
      // …while an actual proxy switch evicts and re-dials.
      await updated("corp")
      expect(await (await post()).text()).toContain("data: [DONE]")
      expect(connections).toBe(2)
      await hooks.dispose?.()
    } finally {
      for (const socket of wss.clients) socket.terminate()
      wss.close()
      http.close()
    }
  })

  test("filters unsupported modes and uses Codex context limits for OAuth GPT models", async () => {
    const hooks = await CodexAuthPlugin({} as never)
    const limit = { context: 1_050_000, input: 922_000, output: 128_000 }
    const provider = {
      models: {
        ...Object.fromEntries(
          [
            "gpt-5.4",
            "gpt-5.5",
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
            "gpt-5.7-pro",
            "gpt-6-sol",
            "gpt-6-luna",
          ].map((id) => [id, { id, api: { id }, limit, cost: {}, options: {} }]),
        ),
        "gpt-5.4-pro": {
          id: "gpt-5.4-pro",
          api: { id: "gpt-5.4" },
          limit,
          cost: {},
          options: { reasoningMode: "pro" },
        },
        "gpt-5.6-sol-high": {
          id: "gpt-5.6-sol-high",
          api: { id: "gpt-5.6-sol" },
          limit,
          cost: {},
          options: { reasoningEffort: "high" },
        },
      },
    }

    const models = await hooks.provider!.models!(provider as never, { auth: { type: "oauth" } } as never)

    expect(models["gpt-5.4"]?.limit).toEqual(limit)
    expect(models["gpt-5.5"]?.limit).toEqual({ context: 400_000, input: 272_000, output: 128_000 })
    expect(models["gpt-5.6-sol"]?.limit).toEqual({ context: 400_000, input: 272_000, output: 128_000 })
    expect(models["gpt-5.6-terra"]?.limit).toEqual({ context: 400_000, input: 272_000, output: 128_000 })
    expect(models["gpt-5.6-luna"]?.limit).toEqual({ context: 400_000, input: 272_000, output: 128_000 })
    expect(models["gpt-6-sol"]).toBeDefined()
    expect(models["gpt-6-luna"]).toBeDefined()
    expect(models["gpt-5.4-pro"]).toBeUndefined()
    expect(models["gpt-5.7-pro"]).toBeDefined()
    expect(models["gpt-5.6-sol-high"]).toBeDefined()
    expect(await hooks.provider!.models!(provider as never, { auth: { type: "api" } } as never)).toBe(
      provider.models as never,
    )
  })

  test.each([
    ["gpt-6-astra", true],
    ["gpt-6", true],
    ["gpt-6.0-astra", true],
    ["gpt-7", true],
    ["gpt-10", true],
    ["gpt-5.5-astra", true],
    ["gpt-5.9", true],
    ["gpt-5.10", true],
    ["gpt-5.10-astra", true],
    ["gpt-5.40", true],
    ["gpt-5", false],
    ["gpt-5.4-astra", false],
    ["gpt-5.04-astra", false],
    ["gpt-4.1", false],
    ["gpt-4.99", false],
    ["gpt-5.5-pro", false],
    ["gpt-5.6", false],
    ["gpt-6garbage", true],
    ["gpt-6.", true],
    ["gpt-6.1.2", true],
    ["not-a-gpt-model", false],
  ])("filters OAuth model %s by GPT major and minor versions", async (id, allowed) => {
    const hooks = await CodexAuthPlugin({} as never)
    const provider = {
      models: {
        [id]: { id, api: { id }, limit: {}, cost: {}, options: {} },
      },
    }

    const models = await hooks.provider!.models!(provider as never, { auth: { type: "oauth" } } as never)

    expect(Object.keys(models)).toEqual(allowed ? [id] : [])
  })

  test("deduplicates concurrent Codex token refreshes", async () => {
    const refreshedAccess = createTestJwt({
      "https://api.openai.com/auth": { chatgpt_compute_residency: "eu" },
    })
    let auth = {
      type: "oauth" as const,
      refresh: "refresh-old",
      access: "",
      expires: 0,
    }
    const authUpdates: Array<{
      body: { refresh: string; access: string; expires: number; accountId?: string }
    }> = []
    let resolveRefresh: (() => void) | undefined
    const refreshReady = new Promise<void>((resolve) => {
      resolveRefresh = resolve
    })
    let refreshRequests = 0
    const apiRequests: { authorization: string | null; accountId: string | null; residency: string | null }[] = []

    using server = Bun.serve({
      port: 0,
      async fetch(request) {
        const url = new URL(request.url)
        if (url.pathname === "/oauth/token") {
          expect(await request.text()).toContain("refresh_token=refresh-old")
          refreshRequests += 1
          await refreshReady
          return Response.json({
            id_token: createTestJwt({ chatgpt_account_id: "acc-123" }),
            access_token: refreshedAccess,
            refresh_token: "refresh-new",
            expires_in: 3600,
          })
        }

        if (url.pathname === "/backend-api/codex/responses") {
          apiRequests.push({
            authorization: request.headers.get("authorization"),
            accountId: request.headers.get("ChatGPT-Account-Id"),
            residency: request.headers.get("x-openai-internal-codex-residency"),
          })
          return new Response("{}", { status: 200 })
        }

        return new Response("unexpected request", { status: 500 })
      },
    })

    const hooks = await CodexAuthPlugin(
      {
        client: {
          auth: {
            async set(input: { body: { refresh: string; access: string; expires: number; accountId?: string } }) {
              authUpdates.push(input)
              auth = {
                type: "oauth",
                refresh: input.body.refresh,
                access: input.body.access,
                expires: input.body.expires,
                ...(input.body.accountId && { accountId: input.body.accountId }),
              }
            },
          },
        } as never,
        project: {} as never,
        directory: "",
        worktree: "",
        experimental_workspace: {
          register() {},
        },
        serverUrl: new URL("https://example.com"),
        $: {} as never,
      },
      {
        issuer: server.url.origin,
        codexApiEndpoint: new URL("/backend-api/codex/responses", server.url).toString(),
      },
    )
    const loaded = await hooks.auth!.loader!(async () => auth as never, {} as never)

    const first = loaded.fetch!("https://api.openai.com/v1/responses")
    const second = loaded.fetch!("https://api.openai.com/v1/responses")

    await waitFor(() => refreshRequests === 1)
    expect(apiRequests).toHaveLength(0)

    resolveRefresh!()
    await Promise.all([first, second])

    expect(refreshRequests).toBe(1)
    expect(authUpdates).toHaveLength(1)
    expect(authUpdates[0]?.body.refresh).toBe("refresh-new")
    expect(authUpdates[0]?.body.access).toBe(refreshedAccess)
    expect(authUpdates[0]?.body.accountId).toBe("acc-123")
    expect(apiRequests).toEqual([
      { authorization: `Bearer ${refreshedAccess}`, accountId: "acc-123", residency: "eu" },
      { authorization: `Bearer ${refreshedAccess}`, accountId: "acc-123", residency: "eu" },
    ])
  })
})

async function waitFor(predicate: () => boolean) {
  const started = Date.now()
  while (!predicate()) {
    if (Date.now() - started > 1_000) throw new Error("timed out waiting for condition")
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
}

describe("resolveSessionProxy", () => {
  // Module caches (last-good table, eviction tracker) leak across tests in
  // this file — reset before each resolver case for determinism.
  beforeEach(() => {
    resetProxyConfigCache()
    lastSeenProxyID.clear()
  })
  const entry = (overrides: Record<string, unknown> = {}) => ({
    name: "Corp",
    type: "http",
    url: "127.0.0.1:8080",
    ...overrides,
  })
  const config = (proxies: Record<string, unknown>) => ({ proxies }) as never
  const clientFor = (session: unknown, proxy: unknown) =>
    ({
      session: { get: async () => ({ data: session }) },
      config: { get: async () => ({ data: { proxy } }) },
    }) as never

  test("returns the entry URL with credentials for explicit choices", async () => {
    process.env.CODEX_PROXY_TEST_PASS = "s3cret"
    try {
      const client = clientFor(
        { proxyID: "corp" },
        config({ corp: entry({ username: "bot", passwordEnv: "CODEX_PROXY_TEST_PASS" }) }),
      )
      const url = await resolveSessionProxy(client as never, "session-1", "wss://example.com/backend-api/x")
      expect(url).toBe("http://bot:s3cret@127.0.0.1:8080/")
    } finally {
      delete process.env.CODEX_PROXY_TEST_PASS
    }
  })

  test("returns undefined for direct resolutions", async () => {
    const client = clientFor({ proxyID: "direct" }, config({}))
    expect(await resolveSessionProxy(client as never, "session-1", "wss://example.com/x")).toBeUndefined()
  })

  test("falls back to config default when the session is gone", async () => {
    const failing = {
      session: {
        get: async () => {
          throw new Error("gone")
        },
      },
      config: {
        get: async () => ({ data: { proxy: { default: "corp", proxies: { corp: entry() } } } }),
      },
    } as never
    // Session read fails → proxyID undefined → config default "corp" wins.
    expect(await resolveSessionProxy(failing as never, "missing", "wss://example.com/x")).toBe(
      "http://127.0.0.1:8080/",
    )
  })

  test("honors per-host noProxy rules against the real target", async () => {
    const bypassed = {
      session: {
        get: async () => {
          throw new Error("gone")
        },
      },
      config: {
        get: async () => ({
          data: { proxy: { default: "corp", proxies: { corp: entry({ noProxy: ["example.com"] }) } } },
        }),
      },
    } as never
    expect(await resolveSessionProxy(bypassed as never, "missing", "wss://example.com/x")).toBeUndefined()
  })

  test("throws on unknown proxy ids instead of going direct", async () => {
    const client = clientFor({ proxyID: "nope" }, config({}))
    await expect(resolveSessionProxy(client as never, "session-1", "wss://example.com/x")).rejects.toThrow(
      "Unknown proxy: nope",
    )
  })

  test("fails loud on config read failures with nothing cached", async () => {
    // An unreadable config with no prior good read means the default is
    // unknowable: swallowing it would silently bypass a required proxy in
    // favor of env/direct.
    resetProxyConfigCache()
    lastSeenProxyID.clear()
    const client = {
      session: { get: async () => ({ data: {} }) },
      config: {
        get: async () => {
          throw new Error("config store unavailable")
        },
      },
    } as never
    await expect(resolveSessionProxy(client, undefined, "wss://example.com/x")).rejects.toThrow(
      "Proxy config unavailable",
    )
  })

  test("degrades to the last good table during a transient config outage", async () => {
    resetProxyConfigCache()
    lastSeenProxyID.clear()
    const table = { default: "corp", proxies: { corp: entry() } }
    const good = {
      session: { get: async () => ({ data: {} }) },
      config: { get: async () => ({ data: { proxy: table } }) },
    } as never
    expect(await resolveSessionProxy(good, undefined, "wss://example.com/x")).toBe("http://127.0.0.1:8080/")
    const blip = {
      session: { get: async () => ({ data: {} }) },
      config: {
        get: async () => {
          throw new Error("config store unavailable")
        },
      },
    } as never
    expect(await resolveSessionProxy(blip, undefined, "wss://example.com/x")).toBe("http://127.0.0.1:8080/")
  })

  test("seeds the eviction tracker from the resolving read", async () => {
    resetProxyConfigCache()
    lastSeenProxyID.clear()
    const client = clientFor({ proxyID: "corp" }, config({ corp: entry() }))
    expect(await resolveSessionProxy(client as never, "session-9", "wss://example.com/x")).toBe(
      "http://127.0.0.1:8080/",
    )
    // The dial-time read seeded the tracker: an update carrying the same
    // choice must not evict, and a pre-tracker switch still would.
    expect(lastSeenProxyID.get("session-9")).toBe("corp")
  })

  test("propagates config read failures instead of misreporting unknown proxy", async () => {
    resetProxyConfigCache()
    lastSeenProxyID.clear()
    const client = {
      session: { get: async () => ({ data: { proxyID: "corp" } }) },
      config: {
        get: async () => {
          throw new Error("config store unavailable")
        },
      },
    } as never
    // Swallowing this would pair proxyID "corp" with an empty table and throw
    // a misleading UnknownProxyError; surfacing the real failure matches the
    // session LLM path, which also fails when config is unreadable. (Cached
    // tables are reset above so the failure is genuinely first-run.)
    await expect(resolveSessionProxy(client, "session-1", "wss://example.com/x")).rejects.toThrow(
      "Proxy config unavailable",
    )
  })

  test("accepts URL/Request targets and uppercase WS schemes", async () => {
    const client = clientFor({ proxyID: "corp" }, config({ corp: entry() }))
    const request = new Request("https://other.example/y", { method: "POST" })
    expect(await resolveSessionProxy(client as never, "session-1", new URL("WSS://example.com/x"))).toBe(
      "http://127.0.0.1:8080/",
    )
    expect(await resolveSessionProxy(client as never, "session-1", request)).toBe("http://127.0.0.1:8080/")
  })

  test("extracts URLs from cross-realm-like objects without instanceof", async () => {
    const client = clientFor({ proxyID: "corp" }, config({ corp: entry() }))
    // A cross-realm URL fails `instanceof URL` and has no `.url`: duck-typing
    // on `.href` must still resolve the real target.
    const foreign = { href: "wss://example.com/x", toString: () => "wss://example.com/x" }
    expect(await resolveSessionProxy(client as never, "session-1", foreign as unknown as URL)).toBe(
      "http://127.0.0.1:8080/",
    )
  })
})

async function createCodexWebSocketServer() {
  let headers: IncomingMessage["headers"] | undefined
  const server = createServer()
  const sockets = new WebSocketServer({ server })
  sockets.on("connection", (socket, request) => {
    headers = request.headers
    socket.once("message", () => {
      socket.send(JSON.stringify({ type: "response.completed", response: { id: "resp_123" } }))
    })
  })
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  const address = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${address.port}/backend-api/codex/responses`,
    headers: () => headers,
    async [Symbol.asyncDispose]() {
      for (const socket of sockets.clients) socket.terminate()
      sockets.close()
      server.close()
    },
  }
}
