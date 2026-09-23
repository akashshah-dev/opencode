export * as Proxy from "./proxy"

import { ConfigProxyV1 } from "@opencode-ai/core/v1/config/proxy"

/** Session proxy sentinel that bypasses all proxies. */
export const DIRECT = "direct"
/** Session proxy sentinel that follows HTTPS_PROXY/HTTP_PROXY/ALL_PROXY + NO_PROXY. */
export const SYSTEM = "env"

export type Resolved =
  | { kind: "direct" }
  | { kind: "env"; url: string }
  | { kind: "proxy"; id: string; entry: ConfigProxyV1.Entry; url: string }

export interface ResolveInput {
  proxyID?: string
  proxy?: ConfigProxyV1.Info
  url: string | URL
  env?: Record<string, string | undefined>
}

export class UnknownProxyError extends Error {
  constructor(readonly id: string) {
    super(`Unknown proxy: ${id}`)
    this.name = "UnknownProxyError"
  }
}

export class DisabledProxyError extends Error {
  constructor(readonly id: string) {
    super(`Proxy is disabled: ${id}`)
    this.name = "DisabledProxyError"
  }
}

export class ProxyUrlError extends Error {
  constructor(readonly address: string) {
    super(`Invalid proxy address (must be host:port or full URL without credentials): ${address}`)
    this.name = "ProxyUrlError"
  }
}

export class ProxyAuthError extends Error {
  constructor(readonly variable: string) {
    super(`Proxy password env var is not set: ${variable}`)
    this.name = "ProxyAuthError"
  }
}

const DEFAULT_PORTS: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
}

const RESERVED_IDS = new Set([DIRECT, SYSTEM])

export function validateID(id: string) {
  return /^[a-z0-9][a-z0-9-_]*$/.test(id) && !RESERVED_IDS.has(id)
}

export function isLoopback(hostname: string) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "")
  if (host === "localhost" || host.endsWith(".localhost")) return true
  if (host === "::1") return true
  return /^127\.(\d{1,3}\.){2}\d{1,3}$/.test(host)
}

// Same matching semantics as NO_PROXY: exact host, host:port, leading-dot or
// leading-star suffix, "*" matches everything. Case-insensitive.
export function matchesNoProxy(hostname: string, port: number, patterns: readonly string[]) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "")
  return splitNoProxy(patterns).some((pattern) => {
    const parsed = pattern.match(/^(.+):(\d+)$/)
    const patternHost = (parsed ? parsed[1] : pattern).replace(/^\[|\]$/g, "")
    const patternPort = parsed ? Number.parseInt(parsed[2]) : 0
    if (patternPort && patternPort !== port) return false
    if (patternHost.startsWith("*")) return host.endsWith(patternHost.slice(1))
    if (patternHost.startsWith(".")) return host.endsWith(patternHost)
    return host === patternHost
  })
}

function splitNoProxy(patterns: readonly string[]) {
  return patterns
    .flatMap((pattern) => pattern.toLowerCase().split(/[,\s]/))
    .map((pattern) => pattern.trim())
    .filter(Boolean)
}

export function parseAddress(address: string, type: ConfigProxyV1.Type) {
  const value = address.trim()
  if (!value) return undefined
  const url = value.includes("://") ? value : `${type}://${value}`
  if (!URL.canParse(url)) return undefined
  const parsed = new URL(url)
  if (!parsed.hostname) return undefined
  if (parsed.username || parsed.password) return undefined
  return parsed
}

function requireAddress(address: string, type: ConfigProxyV1.Type) {
  const parsed = parseAddress(address, type)
  if (!parsed) throw new ProxyUrlError(address)
  return parsed
}

export function buildProxyUrl(entry: ConfigProxyV1.Entry, env: Record<string, string | undefined> = process.env) {
  const parsed = requireAddress(entry.url, entry.type)
  if (entry.username) parsed.username = entry.username
  if (entry.passwordEnv) {
    const password = env[entry.passwordEnv]
    if (!password) throw new ProxyAuthError(entry.passwordEnv)
    parsed.password = password
  }
  return parsed.toString()
}

// Never emit passwords. Keeps the username so errors stay attributable.
export function redactProxyUrl(url: string) {
  if (URL.canParse(url)) {
    const parsed = new URL(url)
    if (parsed.password) parsed.password = "***"
    return parsed.toString()
  }
  // Greedy to the LAST `@`: passwords may contain `/`, whitespace, or `@`
  // themselves — see redactProxyLabel in plugin/openai/ws.ts. Over-redacting
  // an already-invalid string is safe; under-redacting leaks.
  return url.replace(/^(.*:\/\/)?([\s\S]+)@/u, (_, scheme: string | undefined, user: string) => {
    const masked = user.includes(":") ? ":***" : ""
    return `${scheme ?? ""}${user.split(":")[0]}${masked}@`
  })
}

// Short `name@host:port` label for the prompt footer. Falls back to the name
// when the address is invalid so display never throws.
export function displayTarget(entry: ConfigProxyV1.Entry) {
  const parsed = parseAddress(entry.url, entry.type)
  if (!parsed) return entry.name
  return `${entry.name}@${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`
}

// Precedence: explicit session choice -> config default -> system env -> direct.
// Loopback targets bypass remote proxies (which could not reach them anyway)
// but still route through a loopback proxy such as a local forwarder. Unknown
// or disabled ids fail fast instead of silently falling back to direct.
export function resolveForSession(input: ResolveInput): Resolved {
  const target =
    typeof input.url === "string" ? (URL.canParse(input.url) ? new URL(input.url) : undefined) : input.url
  if (!target || !target.hostname) return { kind: "direct" }
  const scheme = target.protocol.replace(/:$/, "")
  const port = target.port ? Number.parseInt(target.port) : (DEFAULT_PORTS[scheme] ?? 0)

  const env = input.env ?? process.env
  const selection = input.proxyID ?? input.proxy?.default ?? SYSTEM

  // Configured entries win over sentinels so existing configs with "direct"/"env"
  // ids keep working. The add-flow reserves these names for new proxies.
  const entry = input.proxy?.proxies?.[selection]
  if (entry) {
    if (entry.enabled === false) throw new DisabledProxyError(selection)
    if (entry.noProxy && matchesNoProxy(target.hostname, port, entry.noProxy)) return { kind: "direct" }
    if (isLoopback(target.hostname) && !isLoopback(hostnameOf(entry.url, entry.type))) return { kind: "direct" }
    return { kind: "proxy", id: selection, entry, url: buildProxyUrl(entry, env) }
  }
  if (selection === DIRECT) return { kind: "direct" }
  if (selection === SYSTEM) {
    const proxy = proxyFromEnv(scheme, target.hostname, port, env)
    if (!proxy) return { kind: "direct" }
    if (isLoopback(target.hostname) && !isLoopback(hostnameOf(proxy, scheme))) return { kind: "direct" }
    return { kind: "env", url: proxy }
  }
  throw new UnknownProxyError(selection)
}

function hostnameOf(address: string, scheme: string) {
  const value = address.trim()
  if (!value) return ""
  const url = value.includes("://") ? value : `${scheme}://${value}`
  if (!URL.canParse(url)) return ""
  return new URL(url).hostname
}

function proxyFromEnv(
  scheme: string,
  hostname: string,
  port: number,
  env: Record<string, string | undefined>,
) {
  const get = (key: string) => env[key.toLowerCase()] ?? env[key.toUpperCase()] ?? ""
  if (matchesNoProxy(hostname, port, [get("no_proxy")])) return undefined
  const proxy = get(`${scheme}_proxy`) || get("all_proxy")
  if (!proxy) return undefined
  return proxy.includes("://") ? proxy : `${scheme}://${proxy}`
}
