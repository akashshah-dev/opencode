import { describe, expect, test } from "bun:test"
import { Proxy } from "../../src/proxy/proxy"

const entry = {
  name: "Corp",
  type: "http",
  url: "proxy.corp:8080",
} as const

const config = {
  default: "corp",
  proxies: {
    corp: { ...entry },
    backup: { name: "Backup", type: "http", url: "backup.corp:8080" },
  },
} as const

describe("resolveForSession", () => {
  test("explicit session choice beats config default", () => {
    const resolved = Proxy.resolveForSession({
      proxyID: "backup",
      proxy: config,
      url: "https://api.openai.com/v1",
      env: {},
    })
    expect(resolved.kind).toBe("proxy")
    if (resolved.kind !== "proxy") return
    expect(resolved.id).toBe("backup")
  })

  test("config default applies without explicit choice", () => {
    const resolved = Proxy.resolveForSession({ proxy: config, url: "https://api.openai.com/v1", env: {} })
    expect(resolved.kind).toBe("proxy")
    if (resolved.kind !== "proxy") return
    expect(resolved.id).toBe("corp")
    expect(resolved.url).toBe("http://proxy.corp:8080/")
  })

  test("falls back to system env without config default", () => {
    const resolved = Proxy.resolveForSession({
      url: "https://api.openai.com/v1",
      env: { HTTPS_PROXY: "https://env-proxy:8443" },
    })
    expect(resolved).toEqual({ kind: "env", url: "https://env-proxy:8443" })
  })

  test("defaults to direct when nothing configured", () => {
    expect(Proxy.resolveForSession({ url: "https://api.openai.com/v1", env: {} })).toEqual({ kind: "direct" })
  })

  test("direct sentinel bypasses everything", () => {
    expect(
      Proxy.resolveForSession({ proxyID: "direct", proxy: config, url: "https://api.openai.com/v1", env: {} }),
    ).toEqual({ kind: "direct" })
  })

  test("env sentinel ignores config default", () => {
    const resolved = Proxy.resolveForSession({
      proxyID: "env",
      proxy: config,
      url: "https://api.openai.com/v1",
      env: { HTTPS_PROXY: "https://env-proxy:8443" },
    })
    expect(resolved).toEqual({ kind: "env", url: "https://env-proxy:8443" })
  })

  test("loopback bypasses remote proxies but routes through loopback proxies", () => {
    for (const url of ["http://localhost:3000/x", "http://127.0.0.1:8080/x", "http://[::1]:8080/x"]) {
      expect(Proxy.resolveForSession({ proxy: config, url, env: {} })).toEqual({ kind: "direct" })
      const routed = Proxy.resolveForSession({
        proxyID: "local",
        proxy: { proxies: { local: { name: "Local", type: "http", url: "127.0.0.1:8888" } } },
        url,
        env: {},
      })
      expect(routed.kind).toBe("proxy")
    }
  })

  test("entry noProxy bypasses matching hosts", () => {
    const resolved = Proxy.resolveForSession({
      proxy: {
        proxies: {
          corp: { ...entry, noProxy: ["internal.corp", "*.svc.cluster.local"] },
        },
      },
      url: "https://api.internal.corp/v1",
      env: {},
    })
    expect(resolved).toEqual({ kind: "direct" })
  })

  test("fails fast on unknown proxy instead of falling back", () => {
    expect(() => Proxy.resolveForSession({ proxyID: "nope", proxy: config, url: "https://x.test", env: {} })).toThrow(
      Proxy.UnknownProxyError,
    )
  })

  test("fails fast on disabled proxy", () => {
    expect(() =>
      Proxy.resolveForSession({
        proxy: { default: "corp", proxies: { corp: { ...entry, enabled: false } } },
        url: "https://x.test",
        env: {},
      }),
    ).toThrow(Proxy.DisabledProxyError)
  })
})

describe("buildProxyUrl", () => {
  test("injects username and password from env ref", () => {
    const url = Proxy.buildProxyUrl({ ...entry, username: "bot", passwordEnv: "PROXY_PASS" }, { PROXY_PASS: "s3cret" })
    expect(url).toBe("http://bot:s3cret@proxy.corp:8080/")
  })

  test("throws when password env var is missing", () => {
    expect(() => Proxy.buildProxyUrl({ ...entry, passwordEnv: "MISSING" }, {})).toThrow(Proxy.ProxyAuthError)
  })

  test("rejects embedded credentials", () => {
    expect(() => Proxy.buildProxyUrl({ ...entry, url: "http://user:pass@host:8080" }, {})).toThrow(Proxy.ProxyUrlError)
  })
})

describe("redactProxyUrl", () => {
  test("masks password but keeps username", () => {
    expect(Proxy.redactProxyUrl("http://bot:s3cret@proxy.corp:8080/")).toBe("http://bot:***@proxy.corp:8080/")
  })

  test("leaves credential-less urls intact", () => {
    expect(Proxy.redactProxyUrl("http://proxy.corp:8080/")).toBe("http://proxy.corp:8080/")
  })
})

describe("validateID", () => {
  test("accepts slugs, rejects the rest", () => {
    expect(Proxy.validateID("corp-main_1")).toBe(true)
    expect(Proxy.validateID("Corp")).toBe(false)
    expect(Proxy.validateID("-x")).toBe(false)
    expect(Proxy.validateID("")).toBe(false)
  })
})

describe("displayTarget", () => {
  test("renders name@host:port", () => {
    expect(Proxy.displayTarget({ ...entry })).toBe("Corp@proxy.corp:8080")
  })
})
