import { Cause, Context, Effect, Layer, Random } from "effect"
import {
  FetchHttpClient,
  Headers,
  HttpClient,
  HttpClientError,
  HttpClientRequest,
  HttpClientResponse,
} from "effect/unstable/http"
import {
  AuthenticationReason,
  ContentPolicyReason,
  HttpContext,
  HttpRateLimitDetails,
  HttpRequestDetails,
  HttpResponseDetails,
  InvalidRequestReason,
  LLMError,
  ProviderInternalReason,
  QuotaExceededReason,
  RateLimitReason,
  TransportReason,
  UnknownProviderReason,
} from "../schema"
import { isContextOverflow } from "../provider-error"

export interface Interface {
  readonly execute: (
    request: HttpClientRequest.HttpClientRequest,
    options?: { readonly proxy?: string | undefined },
  ) => Effect.Effect<HttpClientResponse.HttpClientResponse, LLMError>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/LLM/RequestExecutor") {}

const BODY_LIMIT = 16_384
const MAX_RETRIES = 2
const BASE_DELAY_MS = 500
const MAX_DELAY_MS = 10_000
const REDACTED = "<redacted>"

// One source of truth for what counts as a sensitive name across headers,
// URL query keys, and field names embedded inside request/response bodies.
//
// `SENSITIVE_NAME` is used as both a substring matcher (for free-form header
// names like `Authorization` / `X-API-Key`) and as the body-field alternation
// list. `SHORT_QUERY_NAME` covers anchored short keys like `?key=…` / `?sig=…`
// that are too generic to redact substring-style without false positives.
const SENSITIVE_NAME_SOURCE =
  "authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|token|secret|credential|signature|x-amz-signature"
const SENSITIVE_NAME = new RegExp(SENSITIVE_NAME_SOURCE, "i")
const SHORT_QUERY_NAME = /^(key|sig)$/i
const SENSITIVE_BODY_FIELD = new RegExp(`(?:${SENSITIVE_NAME_SOURCE}|key)`, "i")
const REDACT_JSON_FIELD = new RegExp(`("(?:${SENSITIVE_BODY_FIELD.source})"\\s*:\\s*)"[^"]*"`, "gi")
const REDACT_QUERY_FIELD = new RegExp(`((?:${SENSITIVE_BODY_FIELD.source})=)[^&\\s"]+`, "gi")

const isSensitiveHeaderName = (name: string) => SENSITIVE_NAME.test(name)

const isSensitiveQueryName = (name: string) => isSensitiveHeaderName(name) || SHORT_QUERY_NAME.test(name)

const redactHeaders = (headers: Headers.Headers, redactedNames: ReadonlyArray<string | RegExp>) =>
  Object.fromEntries(
    Object.entries(Headers.redact(headers, [...redactedNames, SENSITIVE_NAME])).map(([name, value]) => [
      name,
      String(value),
    ]),
  )

const redactUrl = (value: string) => {
  if (!URL.canParse(value)) return REDACTED
  const url = new URL(value)
  url.searchParams.forEach((_, key) => {
    if (isSensitiveQueryName(key)) url.searchParams.set(key, REDACTED)
  })
  return url.toString()
}

const normalizedHeaders = (headers: Headers.Headers) =>
  Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]))

const requestId = (headers: Record<string, string>) => {
  return (
    headers["x-request-id"] ??
    headers["request-id"] ??
    headers["x-amzn-requestid"] ??
    headers["x-amz-request-id"] ??
    headers["x-goog-request-id"] ??
    headers["cf-ray"]
  )
}

const retryableStatus = (status: number) => status === 429 || status === 503 || status === 504 || status === 529

const retryAfterMs = (headers: Record<string, string>) => {
  const millis = Number(headers["retry-after-ms"])
  if (Number.isFinite(millis)) return Math.max(0, millis)

  const value = headers["retry-after"]
  if (!value) return undefined

  const seconds = Number(value)
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000)

  const date = Date.parse(value)
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now())
  return undefined
}

const addRateLimitValue = (target: Record<string, string>, key: string, value: string) => {
  if (key.length > 0) target[key] = value
}

const rateLimitDetails = (headers: Record<string, string>, retryAfter: number | undefined) => {
  const limit: Record<string, string> = {}
  const remaining: Record<string, string> = {}
  const reset: Record<string, string> = {}

  Object.entries(headers).forEach(([name, value]) => {
    const openaiLimit = /^x-ratelimit-limit-(.+)$/.exec(name)?.[1]
    if (openaiLimit) return addRateLimitValue(limit, openaiLimit, value)

    const openaiRemaining = /^x-ratelimit-remaining-(.+)$/.exec(name)?.[1]
    if (openaiRemaining) return addRateLimitValue(remaining, openaiRemaining, value)

    const openaiReset = /^x-ratelimit-reset-(.+)$/.exec(name)?.[1]
    if (openaiReset) return addRateLimitValue(reset, openaiReset, value)

    const anthropic = /^anthropic-ratelimit-(.+)-(limit|remaining|reset)$/.exec(name)
    if (!anthropic) return
    if (anthropic[2] === "limit") return addRateLimitValue(limit, anthropic[1], value)
    if (anthropic[2] === "remaining") return addRateLimitValue(remaining, anthropic[1], value)
    return addRateLimitValue(reset, anthropic[1], value)
  })

  if (
    retryAfter === undefined &&
    Object.keys(limit).length === 0 &&
    Object.keys(remaining).length === 0 &&
    Object.keys(reset).length === 0
  )
    return undefined

  return new HttpRateLimitDetails({
    retryAfterMs: retryAfter,
    limit: Object.keys(limit).length === 0 ? undefined : limit,
    remaining: Object.keys(remaining).length === 0 ? undefined : remaining,
    reset: Object.keys(reset).length === 0 ? undefined : reset,
  })
}

const requestDetails = (request: HttpClientRequest.HttpClientRequest, redactedNames: ReadonlyArray<string | RegExp>) =>
  new HttpRequestDetails({
    method: request.method,
    url: redactUrl(request.url),
    headers: redactHeaders(request.headers, redactedNames),
  })

const responseDetails = (
  response: HttpClientResponse.HttpClientResponse,
  redactedNames: ReadonlyArray<string | RegExp>,
) =>
  new HttpResponseDetails({
    status: response.status,
    headers: redactHeaders(response.headers, redactedNames),
  })

const secretValues = (request: HttpClientRequest.HttpClientRequest) => {
  const values = new Set<string>()
  const add = (value: string) => {
    if (value.length < 4) return
    values.add(value)
    values.add(encodeURIComponent(value))
  }

  Object.entries(request.headers).forEach(([name, value]) => {
    if (!isSensitiveHeaderName(name)) return
    add(value)
    const bearer = /^Bearer\s+(.+)$/i.exec(value)?.[1]
    if (bearer) add(bearer)
  })

  if (!URL.canParse(request.url)) return values
  new URL(request.url).searchParams.forEach((value, key) => {
    if (isSensitiveQueryName(key)) add(value)
  })
  return values
}

// Two passes: structural (redact `"name": "value"` and `name=value` patterns
// for any field name that looks sensitive) plus literal (replace any actual
// secret values we sent in the request, in case the response echoes one back).
const redactBody = (body: string, request: HttpClientRequest.HttpClientRequest) =>
  Array.from(secretValues(request)).reduce(
    (text, secret) => text.split(secret).join(REDACTED),
    body.replace(REDACT_JSON_FIELD, `$1"${REDACTED}"`).replace(REDACT_QUERY_FIELD, `$1${REDACTED}`),
  )

const responseBody = (body: string | void, request: HttpClientRequest.HttpClientRequest) => {
  if (body === undefined) return {}
  const redacted = redactBody(body, request)
  if (redacted.length <= BODY_LIMIT) return { body: redacted }
  return { body: redacted.slice(0, BODY_LIMIT), bodyTruncated: true }
}

const providerMessage = (status: number, body: { readonly body?: string }) => {
  if (body.body && body.body.length <= 500) return `Provider request failed with HTTP ${status}: ${body.body}`
  return `Provider request failed with HTTP ${status}`
}

const responseHttp = (input: {
  readonly request: HttpClientRequest.HttpClientRequest
  readonly response: HttpClientResponse.HttpClientResponse
  readonly redactedNames: ReadonlyArray<string | RegExp>
  readonly body: ReturnType<typeof responseBody>
  readonly requestId?: string | undefined
  readonly rateLimit?: HttpRateLimitDetails | undefined
}) =>
  new HttpContext({
    request: requestDetails(input.request, input.redactedNames),
    response: responseDetails(input.response, input.redactedNames),
    ...input.body,
    requestId: input.requestId,
    rateLimit: input.rateLimit,
  })

const statusReason = (input: {
  readonly status: number
  readonly message: string
  readonly retryAfterMs?: number | undefined
  readonly rateLimit?: HttpRateLimitDetails | undefined
  readonly http: HttpContext
}) => {
  const body = input.http.body ?? ""
  if (/content[-_\s]?policy|content_filter|safety/i.test(body)) {
    return new ContentPolicyReason({ message: input.message, http: input.http })
  }
  if (input.status === 401) {
    return new AuthenticationReason({ message: input.message, kind: "invalid", http: input.http })
  }
  if (input.status === 403) {
    return new AuthenticationReason({ message: input.message, kind: "insufficient-permissions", http: input.http })
  }
  if (input.status === 429) {
    if (/insufficient[-_\s]?quota|quota[-_\s]?exceeded/i.test(body)) {
      return new QuotaExceededReason({ message: input.message, http: input.http })
    }
    return new RateLimitReason({
      message: input.message,
      retryAfterMs: input.retryAfterMs,
      rateLimit: input.rateLimit,
      http: input.http,
    })
  }
  if (
    input.status === 400 ||
    input.status === 404 ||
    input.status === 409 ||
    input.status === 413 ||
    input.status === 422
  ) {
    return new InvalidRequestReason({
      message: input.message,
      classification: isContextOverflow(body) ? "context-overflow" : undefined,
      http: input.http,
    })
  }
  if (input.status >= 500 || retryableStatus(input.status)) {
    return new ProviderInternalReason({
      message: input.message,
      status: input.status,
      retryAfterMs: input.retryAfterMs,
      http: input.http,
    })
  }
  return new UnknownProviderReason({ message: input.message, status: input.status, http: input.http })
}

const statusError =
  (request: HttpClientRequest.HttpClientRequest, redactedNames: ReadonlyArray<string | RegExp>) =>
  (response: HttpClientResponse.HttpClientResponse) =>
    Effect.gen(function* () {
      if (response.status < 400) return response
      const body = yield* response.text.pipe(Effect.catch(() => Effect.void))
      const headers = normalizedHeaders(response.headers)
      const retryAfter = retryAfterMs(headers)
      const rateLimit = rateLimitDetails(headers, retryAfter)
      const details = responseBody(body, request)
      return yield* new LLMError({
        module: "RequestExecutor",
        method: "execute",
        reason: statusReason({
          status: response.status,
          message: providerMessage(response.status, details),
          retryAfterMs: retryAfter,
          rateLimit,
          http: responseHttp({
            request,
            response,
            redactedNames,
            body: details,
            requestId: requestId(headers),
            rateLimit,
          }),
        }),
      })
    })

const toHttpError = (redactedNames: ReadonlyArray<string | RegExp>) => (error: unknown) => {
  const transportError = (input: {
    readonly message: string
    readonly kind?: string | undefined
    readonly request?: HttpClientRequest.HttpClientRequest | undefined
  }) =>
    new LLMError({
      module: "RequestExecutor",
      method: "execute",
      reason: new TransportReason({
        message: input.message,
        kind: input.kind,
        url: input.request ? redactUrl(input.request.url) : undefined,
        http: input.request ? new HttpContext({ request: requestDetails(input.request, redactedNames) }) : undefined,
      }),
    })

  if (Cause.isTimeoutError(error)) {
    return transportError({ message: error.message, kind: "Timeout" })
  }
  if (!HttpClientError.isHttpClientError(error)) {
    return transportError({ message: "HTTP transport failed" })
  }
  const request = "request" in error ? error.request : undefined
  if (error.reason._tag === "TransportError") {
    return transportError({
      message: error.reason.description ?? "HTTP transport failed",
      kind: error.reason._tag,
      request,
    })
  }
  return transportError({
    message: `HTTP transport failed: ${error.reason._tag}`,
    kind: error.reason._tag,
    request,
  })
}

const retryDelay = (error: LLMError, attempt: number) => {
  if (error.retryAfterMs !== undefined) return Effect.succeed(Math.min(error.retryAfterMs, MAX_DELAY_MS))
  return Random.nextBetween(
    Math.min(BASE_DELAY_MS * 2 ** attempt * 0.8, MAX_DELAY_MS),
    Math.min(BASE_DELAY_MS * 2 ** attempt * 1.2, MAX_DELAY_MS),
  ).pipe(Effect.map((delay) => Math.round(delay)))
}

const retryStatusFailures = <A, R>(
  effect: Effect.Effect<A, LLMError, R>,
  retries = MAX_RETRIES,
  attempt = 0,
): Effect.Effect<A, LLMError, R> =>
  Effect.catchTag(effect, "LLM.Error", (error): Effect.Effect<A, LLMError, R> => {
    if (!error.retryable || retries <= 0) return Effect.fail(error)
    return retryDelay(error, attempt).pipe(
      Effect.flatMap((delay) => Effect.sleep(delay)),
      Effect.flatMap(() => retryStatusFailures(effect, retries - 1, attempt + 1)),
    )
  })

export const layer: Layer.Layer<Service, never, HttpClient.HttpClient> = Layer.effect(
  Service,
  Effect.gen(function* () {
    const http = yield* HttpClient.HttpClient
    const executeOnce = (request: HttpClientRequest.HttpClientRequest, options?: { readonly proxy?: string }) =>
      Effect.gen(function* () {
        const redactedNames = yield* Headers.CurrentRedactedNames
        if (options?.proxy && !shouldBypassProxy(request.url)) {
          return yield* executeProxied(request, options.proxy, redactedNames)
        }
        return yield* http
          .execute(request)
          .pipe(Effect.mapError(toHttpError(redactedNames)), Effect.flatMap(statusError(request, redactedNames)))
      })
    return Service.of({
      execute: (request, options) => retryStatusFailures(executeOnce(request, options)),
    })
  }),
)

// Defense-in-depth: honor NO_PROXY/no_proxy for the executor path even though
// the primary noProxy enforcement lives in the caller (session/llm resolves
// against the real target, ProxyFetch re-resolves per request). Config-entry
// noProxy lists are enforced by the caller; this only covers env.
const shouldBypassProxy = (url: string) => {
  if (!URL.canParse(url)) return false
  const target = new URL(url)
  const port = target.port ? Number(target.port) : target.protocol === "https:" ? 443 : 80
  const raw = process.env["NO_PROXY"] ?? process.env["no_proxy"] ?? ""
  if (!raw.trim()) return false
  const patterns = raw.toLowerCase().split(/[,\s]/).map((s) => s.trim()).filter(Boolean)
  const host = target.hostname.toLowerCase().replace(/^\[|\]$/g, "")
  return patterns.some((pattern) => {
    const parsed = pattern.match(/^(.+):(\d+)$/)
    const patternHost = (parsed ? parsed[1] : pattern).replace(/^\[|\]$/g, "")
    const patternPort = parsed ? Number.parseInt(parsed[2]) : 0
    if (patternPort && patternPort !== port) return false
    if (patternHost.startsWith("*")) return host.endsWith(patternHost.slice(1))
    if (patternHost.startsWith(".")) return host.endsWith(patternHost)
    return host === patternHost
  })
}

export const fetchLayer = layer.pipe(Layer.provide(FetchHttpClient.layer))

export * as RequestExecutor from "./executor"

// Native proxy execution without new dependencies: the proxy URL carries
// everything (scheme selects CONNECT/SOCKS handling, userinfo carries auth).
// Proxy-Authorization belongs on the proxy leg only (CONNECT / plain-HTTP
// forward) and must never travel inside the TLS tunnel to the origin.
// Per-host noProxy bypass is enforced by the caller (ProxyFetch per-request
// resolution, or session/llm resolving against the real target host) — the
// executor only keeps the loopback guard as defense-in-depth.
// Abort propagates via Effect interruption (see connectSocket/httpOverSocket);
// callers should interrupt the stream fiber when their AbortSignal fires.
const executeProxied = (
  request: HttpClientRequest.HttpClientRequest,
  proxyUrl: string,
  redactedNames: ReadonlyArray<string | RegExp>,
): Effect.Effect<HttpClientResponse.HttpClientResponse, LLMError> =>
  Effect.gen(function* () {
    const proxy = new URL(proxyUrl)
    const target = new URL(request.url)
    if (isLoopbackHost(target.hostname) && !isLoopbackHost(proxy.hostname)) {
      return yield* new LLMError({
        module: "RequestExecutor",
        method: "execute",
        reason: new TransportReason({
          message: "Proxy cannot reach loopback target",
          kind: "proxy",
          url: redactUrl(request.url),
        }),
      })
    }
    const auth =
      proxy.username || proxy.password
        ? `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}`
        : undefined
    if (proxy.protocol === "socks4:" || proxy.protocol === "socks5:" || proxy.protocol === "socks5h:") {
      return yield* executeSocks(request, proxy, target, redactedNames)
    }
    if (target.protocol === "https:") {
      return yield* executeTunnel(request, proxy, target, auth, redactedNames)
    }
    const headers = Headers.setAll(Headers.fromInput(request.headers), [
      ...(auth ? [["proxy-authorization", auth] as const] : []),
    ])
    const proxied = HttpClientRequest.setHeaders(request, headers)
    return yield* executeForward(proxied, proxy, target, redactedNames)
  }).pipe(
    Effect.mapError((error: unknown) =>
      LLMErrorType.guard(error)
        ? error
        : toHttpError(redactedNames)({
            reason: { _tag: "TransportError", description: error instanceof Error ? error.message : String(error) },
            request,
          } as never),
    ),
  )

const LLMErrorType = {
  guard: (error: unknown): error is LLMError =>
    typeof error === "object" && error !== null && "_tag" in error && (error as { _tag: unknown })._tag === "LLM.Error",
}

const isLoopbackHost = (hostname: string) => {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "")
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true
  return /^127\.(\d{1,3}\.){2}\d{1,3}$/.test(host)
}

const proxyPort = (proxy: URL) => Number(proxy.port) || (proxy.protocol === "https:" ? 443 : 80)

// Only proven IP literals skip SNI: reuse the strict SOCKS address parsers
// so invalid numerics ("999.999.999.999") and non-literals containing a
// colon keep `servername` instead of silently losing SNI.
const isIPLiteral = (hostname: string) => {
  const host = hostname.replace(/^\[|\]$/g, "")
  return parseIPv4(host) !== undefined || parseIPv6(host) !== undefined
}

// SNI must not carry IP literals (rejected outright, and forbidden by
// RFC 6066), so they are omitted there. Calibration showed the default
// verification path still checks IP SANs (accepts the right cert, rejects a
// wrong-name cert), while the exported checkServerIdentity mishandles IP
// SANs — so IP literals rely on defaults and DNS names use `servername`.
const tlsServerOptions = (hostname: string) => (isIPLiteral(hostname) ? {} : { servername: hostname })

// TLS-wrap the proxy leg itself when the proxy URL is `https:`. Without this,
// CONNECT + Proxy-Authorization would travel in cleartext to a proxy that
// expects TLS (and the handshake would fail).
const secureProxySocket = (socket: import("node:net").Socket, proxy: URL) =>
  proxy.protocol === "https:"
    ? tlsOverSocket(socket, proxy.hostname).pipe(Effect.onError(() => Effect.sync(() => socket.destroy())))
    : Effect.succeed(socket)

// Plain-HTTP target: absolute-form request line to the proxy.
// Abort flows via Effect interruption (the stream is interrupted when the
// caller's AbortSignal fires); every socket helper destroys its socket on
// interrupt so cancelled requests never hang until the proxy times out.
// Socket lifetime is tied to the body stream (destroyed in httpBodyStream's
// finally), not to the headers Effect — destroying on headers would truncate
// split bodies whose second packet arrives after the head Effect completes.
const executeForward = (
  request: HttpClientRequest.HttpClientRequest,
  proxy: URL,
  target: URL,
  redactedNames: ReadonlyArray<string | RegExp>,
) =>
  Effect.gen(function* () {
    const raw = yield* connectSocket(proxy.hostname, proxyPort(proxy))
    const socket = yield* secureProxySocket(raw, proxy)
    const response = yield* httpOverSocket(socket, {
      method: request.method,
      path: target.href,
      host: target.host,
      headers: requestHeaders(request),
      body: yield* requestBody(request),
    }).pipe(Effect.onError(() => Effect.sync(() => socket.destroy())))
    return yield* toClientResponse(response, request, redactedNames)
  })

// HTTPS target: CONNECT tunnel, then TLS to the target over the tunnel.
const executeTunnel = (
  request: HttpClientRequest.HttpClientRequest,
  proxy: URL,
  target: URL,
  auth: string | undefined,
  redactedNames: ReadonlyArray<string | RegExp>,
) =>
  Effect.gen(function* () {
    const raw = yield* connectSocket(proxy.hostname, proxyPort(proxy))
    const socket = yield* secureProxySocket(raw, proxy)
    const tunnel = yield* connectTunnelSocket(socket, proxy, target, auth).pipe(
      Effect.onError(() => Effect.sync(() => socket.destroy())),
    )
    // The raw proxy socket is wrapped by TLS; the TLS socket owns the
    // lifetime now and destroys the underlying socket with it.
    const response = yield* httpOverSocket(tunnel, {
      method: request.method,
      path: `${target.pathname}${target.search}`,
      host: target.host,
      headers: requestHeaders(request),
      body: yield* requestBody(request),
    }).pipe(Effect.onError(() => Effect.sync(() => tunnel.destroy())))
    return yield* toClientResponse(response, request, redactedNames)
  })

// SOCKS target: handshake via a minimal inline SOCKS5/4 client, then HTTP.
const executeSocks = (
  request: HttpClientRequest.HttpClientRequest,
  proxy: URL,
  target: URL,
  redactedNames: ReadonlyArray<string | RegExp>,
) =>
  Effect.gen(function* () {
    const port = Number(target.port) || (target.protocol === "https:" ? 443 : 80)
    const socket = yield* socksConnect({
      host: proxy.hostname,
      port: Number(proxy.port) || 1080,
      type: proxy.protocol === "socks4:" ? 4 : 5,
      userId: proxy.username ? decodeURIComponent(proxy.username) : undefined,
      password: proxy.password ? decodeURIComponent(proxy.password) : undefined,
      destination: target.hostname,
      destinationPort: port,
      // Only socks5h resolves through the proxy; plain socks5 resolves
      // locally first (documented socks5 vs socks5h distinction).
      remoteDNS: proxy.protocol === "socks5h:",
    })
    if (target.protocol === "https:") {
      const tls = yield* tlsOverSocket(socket, target.hostname).pipe(
        Effect.onError(() => Effect.sync(() => socket.destroy())),
      )
      const response = yield* httpOverSocket(tls, {
        method: request.method,
        path: `${target.pathname}${target.search}`,
        host: target.host,
        headers: requestHeaders(request),
        body: yield* requestBody(request),
      }).pipe(Effect.onError(() => Effect.sync(() => tls.destroy())))
      return yield* toClientResponse(response, request, redactedNames)
    }
    const response = yield* httpOverSocket(socket, {
      method: request.method,
      path: target.href,
      host: target.host,
      headers: requestHeaders(request),
      body: yield* requestBody(request),
    }).pipe(Effect.onError(() => Effect.sync(() => socket.destroy())))
    return yield* toClientResponse(response, request, redactedNames)
  })

const requestHeaders = (request: HttpClientRequest.HttpClientRequest): Array<[string, string]> => {
  const headers: Array<[string, string]> = []
  for (const [name, value] of Object.entries(request.headers)) {
    const lower = name.toLowerCase()
    if (lower === "host") continue
    // Defense-in-depth: Proxy-Authorization must never travel inside the TLS
    // tunnel or to the origin. It belongs on the CONNECT / forward leg only.
    if (lower === "proxy-authorization") continue
    if (Array.isArray(value)) {
      for (const item of value) headers.push([name, item])
      continue
    }
    headers.push([name, value])
  }
  return headers
}

const requestBody = (
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<string | Uint8Array | undefined, LLMError> =>
  Effect.gen(function* () {
    if (request.body._tag === "Empty") return undefined
    if (request.body._tag === "Uint8Array") return request.body.body
    const fail = (message: string) =>
      new LLMError({
        module: "RequestExecutor",
        method: "execute",
        reason: new TransportReason({ message, kind: "proxy" }),
      })
    if (request.body._tag === "Raw") {
      const body = request.body.body
      if (typeof body === "string" || body instanceof Uint8Array) return body
      return yield* fail("Unsupported proxied request body")
    }
    return yield* fail("Unsupported proxied request body")
  })

const abortMessage = (signal: AbortSignal) =>
  signal.reason instanceof Error ? signal.reason.message : "aborted"

const connectSocket = (host: string, port: number) =>
  Effect.callback<import("node:net").Socket, LLMError>((resume, signal) => {
    let socket: import("node:net").Socket | undefined
    let settled = false
    const fail = (message: string) => {
      if (settled) return
      settled = true
      signal.removeEventListener("abort", onAbort)
      socket?.destroy(signal.reason ?? new Error("aborted"))
      resume(
        Effect.fail(
          new LLMError({
            module: "RequestExecutor",
            method: "execute",
            reason: new TransportReason({ message, kind: "proxy" }),
          }),
        ),
      )
    }
    const onAbort = () => fail(abortMessage(signal))
    if (signal.aborted) {
      fail(abortMessage(signal))
      return
    }
    signal.addEventListener("abort", onAbort, { once: true })
    import("node:net")
      .then(({ connect }) => {
        if (settled) return
        socket = connect({ host, port })
        socket.once("error", (cause) => fail(`Proxy connection failed: ${cause.message}`))
        socket.once("connect", () => {
          if (settled) return
          settled = true
          signal.removeEventListener("abort", onAbort)
          resume(Effect.succeed(socket!))
        })
      })
      .catch((cause) =>
        fail(`Proxy connection failed: ${cause instanceof Error ? cause.message : String(cause)}`),
      )
  })

const connectTunnelSocket = (
  socket: import("node:net").Socket,
  proxy: URL,
  target: URL,
  auth: string | undefined,
) =>
  Effect.callback<import("node:net").Socket, LLMError>((resume, signal) => {
    void proxy
    let settled = false
    let tls: import("node:tls").TLSSocket | undefined
    let head = Buffer.alloc(0)
    const fail = (message: string) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      tls?.destroy()
      resume(
        Effect.fail(
          new LLMError({
            module: "RequestExecutor",
            method: "execute",
            reason: new TransportReason({ message, kind: "proxy" }),
          }),
        ),
      )
    }
    const cleanup = () => {
      signal.removeEventListener("abort", onAbort)
      socket.off("data", onData)
      socket.off("error", onSocketError)
      socket.off("close", onClose)
      tls?.off("secureConnect", onSecure)
      tls?.off("error", onTlsError)
      tls?.off("close", onTlsClose)
    }
    const onAbort = () => fail(signal.reason instanceof Error ? signal.reason.message : "aborted")
    const onSocketError = (cause: Error) => {
      if (!tls) fail(`Proxy CONNECT failed: ${cause.message}`)
    }
    const onClose = () => {
      if (!tls) fail("Proxy connection closed during CONNECT")
    }
    const onTlsError = (cause: Error) => fail(`TLS failed: ${cause.message}`)
    const onTlsClose = () => fail("TLS connection closed during handshake")
    const onSecure = () => {
      if (settled) return
      settled = true
      cleanup()
      resume(Effect.succeed(tls as unknown as import("node:net").Socket))
    }
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk])
      const end = head.indexOf("\r\n\r\n")
      if (end === -1) return
      socket.off("data", onData)
      socket.off("error", onSocketError)
      socket.off("close", onClose)
      const status = Number(head.subarray(0, end).toString().split("\r\n", 1)[0]?.split(" ", 3)[1])
      if (status !== 200) {
        fail(`Proxy CONNECT failed with status ${status}`)
        return
      }
      const rest = head.subarray(end + 4)
      // NOTE: tls.connect({ socket }) — not `new TLSSocket(socket)` — is the
      // documented STARTTLS-client API; direct construction stalls the
      // handshake on calibration (verified against node 22 + Bun).
      import("node:tls")
        .then(({ connect: tlsConnect }) => {
          if (settled) return
          try {
            tls = tlsConnect({
              socket,
              ALPNProtocols: ["http/1.1"],
              ...tlsServerOptions(target.hostname),
            })
            if (!tls) throw new Error("TLS socket creation returned undefined")
          } catch (cause) {
            fail(`TLS failed: ${cause instanceof Error ? cause.message : String(cause)}`)
            return
          }
          if (rest.length) tls.unshift(rest)
          // Wait for the handshake so HTTP is never written pre-handshake and
          // certificate / CA verification failures surface as TLS errors.
          tls.once("secureConnect", onSecure)
          tls.once("error", onTlsError)
          tls.once("close", onTlsClose)
        })
        .catch((cause) => fail(`Proxy CONNECT failed: ${cause instanceof Error ? cause.message : String(cause)}`))
    }
    if (signal.aborted) {
      fail(signal.reason instanceof Error ? signal.reason.message : "aborted")
      return
    }
    signal.addEventListener("abort", onAbort, { once: true })
    const port = Number(target.port) || 443
    const lines = [`CONNECT ${target.hostname}:${port} HTTP/1.1`, `Host: ${target.hostname}:${port}`]
    if (auth) lines.push(`Proxy-Authorization: ${auth}`)
    lines.push("Proxy-Connection: Keep-Alive", "", "")
    socket.on("data", onData)
    socket.once("error", onSocketError)
    socket.once("close", onClose)
    socket.write(lines.join("\r\n"))
  })

const tlsOverSocket = (socket: import("node:net").Socket, servername: string) =>
  Effect.callback<import("node:net").Socket, LLMError>((resume, signal) => {
    let settled = false
    let tls: import("node:tls").TLSSocket | undefined
    const fail = (message: string) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      tls?.destroy()
      resume(
        Effect.fail(
          new LLMError({
            module: "RequestExecutor",
            method: "execute",
            reason: new TransportReason({ message, kind: "proxy" }),
          }),
        ),
      )
    }
    const cleanup = () => {
      signal.removeEventListener("abort", onAbort)
      tls?.off("secureConnect", onSecure)
      tls?.off("error", onTlsError)
      tls?.off("close", onTlsClose)
    }
    const onAbort = () => fail(signal.reason instanceof Error ? signal.reason.message : "aborted")
    const onTlsError = (cause: Error) => fail(`TLS failed: ${cause.message}`)
    const onTlsClose = () => fail("TLS connection closed during handshake")
    const onSecure = () => {
      if (settled) return
      settled = true
      cleanup()
      resume(Effect.succeed(tls as unknown as import("node:net").Socket))
    }
    if (signal.aborted) {
      fail(signal.reason instanceof Error ? signal.reason.message : "aborted")
      return
    }
    signal.addEventListener("abort", onAbort, { once: true })
    import("node:tls")
      .then(({ connect: tlsConnect }) => {
        if (settled) return
        try {
          tls = tlsConnect({
            socket,
            ALPNProtocols: ["http/1.1"],
            ...tlsServerOptions(servername),
          })
          if (!tls) throw new Error("TLS socket creation returned undefined")
        } catch (cause) {
          fail(`TLS failed: ${cause instanceof Error ? cause.message : String(cause)}`)
          return
        }
        tls.once("secureConnect", onSecure)
        tls.once("error", onTlsError)
        tls.once("close", onTlsClose)
      })
      .catch((cause) => fail(`TLS failed: ${cause instanceof Error ? cause.message : String(cause)}`))
  })

const socksConnect = (input: {
  host: string
  port: number
  type: 4 | 5
  userId?: string
  password?: string
  destination: string
  destinationPort: number
  remoteDNS: boolean
}) =>
  Effect.gen(function* () {
    const socket = yield* connectSocket(input.host, input.port)
    const fail = (message: string) =>
      Effect.gen(function* () {
        yield* Effect.sync(() => socket.destroy())
        return yield* new LLMError({
          module: "RequestExecutor",
          method: "execute",
          reason: new TransportReason({ message, kind: "proxy" }),
        })
      })
    if (input.type === 4) {
      const { lookup } = yield* Effect.promise(() => import("node:dns/promises"))
      const addresses = yield* Effect.promise(() => lookup(input.destination, { all: true })).pipe(
        Effect.catch(() => Effect.succeed([] as Array<{ address: string; family: number }>)),
      )
      const ip = addresses.find((item) => item.family === 4)?.address ?? addresses[0]?.address
      if (!ip) return yield* fail(`SOCKS4 cannot resolve ${input.destination}`)
      const parts = ip.split(".").map(Number)
      if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
        return yield* fail(`SOCKS4 cannot resolve ${input.destination}`)
      }
      const userId = Buffer.from(input.userId ?? "", "utf8")
      const packet = Buffer.concat([
        Buffer.from([0x04, 0x01, (input.destinationPort >> 8) & 0xff, input.destinationPort & 0xff]),
        Buffer.from(parts),
        userId,
        Buffer.from([0x00]),
      ])
      const reply = yield* writeThenRead(socket, packet, 8).pipe(Effect.catch(() => fail("SOCKS4 handshake failed")))
      if (reply[0] !== 0x00 || reply[1] !== 0x5a) return yield* fail(`SOCKS4 rejected (code ${reply[1] ?? "?"})`)
      return socket
    }
    const methods = input.userId !== undefined ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00])
    const greeting = yield* writeThenRead(socket, methods, 2).pipe(Effect.catch(() => fail("SOCKS5 handshake failed")))
    if (greeting[0] !== 0x05) return yield* fail("Invalid SOCKS5 greeting")
    if (greeting[1] === 0xff) return yield* fail("SOCKS5: no acceptable auth method")
    if (greeting[1] === 0x02) {
      const user = Buffer.from(input.userId ?? "", "utf8")
      const pass = Buffer.from(input.password ?? "", "utf8")
      const authPacket = Buffer.concat([
        Buffer.from([0x01, user.length]),
        user,
        Buffer.from([pass.length]),
        pass,
      ])
      const authReply = yield* writeThenRead(socket, authPacket, 2).pipe(
        Effect.catch(() => fail("SOCKS5 auth failed")),
      )
      if (authReply[1] !== 0x00) return yield* fail("SOCKS5 authentication rejected")
    }
    const host = input.remoteDNS ? input.destination : yield* resolveLocal(input.destination)
    const hostBytes = encodeSocksHost(host, input.remoteDNS)
    const connectPacket = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00]),
      hostBytes,
      Buffer.from([(input.destinationPort >> 8) & 0xff, input.destinationPort & 0xff]),
    ])
    const connected = yield* writeThenRead(socket, connectPacket, 4).pipe(
      Effect.catch(() => fail("SOCKS5 connect failed")),
    )
    if (connected[1] !== 0x00) return yield* fail(`SOCKS5 connect rejected (code ${connected[1]})`)
    // Consume the bound address tail (4/16/URI bytes + port) before HTTP.
    const atyp = connected[3] ?? 0x01
    const tail = atyp === 0x04 ? 18 : atyp === 0x03 ? -1 : 8
    if (tail === -1) {
      const lengthByte = yield* readBytes(socket, 1).pipe(Effect.catch(() => fail("SOCKS5 handshake failed")))
      yield* readBytes(socket, (lengthByte[0] ?? 0) + 2).pipe(Effect.catch(() => fail("SOCKS5 handshake failed")))
    } else {
      yield* readBytes(socket, tail).pipe(Effect.catch(() => fail("SOCKS5 handshake failed")))
    }
    return socket
  })

const encodeSocksHost = (host: string, remoteDNS: boolean) => {
  if (!remoteDNS) {
    const ipv4 = parseIPv4(host)
    if (ipv4) return Buffer.concat([Buffer.from([0x01]), ipv4])
    const ipv6 = parseIPv6(host)
    if (ipv6) return Buffer.concat([Buffer.from([0x04]), ipv6])
  }
  const name = Buffer.from(host, "utf8")
  return Buffer.concat([Buffer.from([0x03, name.length]), name])
}

const parseIPv4 = (host: string) => {
  const parts = host.split(".")
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/.test(part))) return undefined
  const bytes = parts.map(Number)
  if (bytes.some((byte) => byte > 255)) return undefined
  return Buffer.from(bytes)
}

// Minimal RFC 4291 parser: 8 hextets with optional "::" compression and an
// optional embedded IPv4 tail as the final 32 bits (e.g. ::ffff:1.2.3.4).
// Returns undefined for non-literals so callers fall back to domain encoding.
const parseIPv6 = (host: string) => {
  if (!host.includes(":")) return undefined
  if (host.includes(".")) {
    // An embedded dotted-quad is only valid as the final part of the address
    // (nothing, including "::", may follow it): reject "1.2.3.4::" and mid
    // address quads so invalid literals use domain encoding instead of
    // wrong ATYP 0x04 bytes.
    const match = /^(.*:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(host)
    if (!match || match[1]?.includes(".")) return undefined
  }
  const halves = host.split("::")
  if (halves.length > 2) return undefined
  const parseGroup = (group: string, isFinal: boolean) => {
    if (group === "") return []
    const parts = group.split(":")
    return parts.flatMap((part, index) => {
      if (part.includes(".")) {
        // Dotted-quad only as the last part of the whole address.
        if (!isFinal || index !== parts.length - 1) throw new Error("invalid")
        const tail = parseIPv4(part)
        if (!tail) throw new Error("invalid")
        return [tail[0]! << 8 | tail[1]!, tail[2]! << 8 | tail[3]!]
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) throw new Error("invalid")
      return [Number.parseInt(part, 16)]
    })
  }
  try {
    const head = parseGroup(halves[0] ?? "", halves.length === 1)
    const tail = halves.length === 2 ? parseGroup(halves[1] ?? "", true) : []
    const missing = 8 - head.length - tail.length
    // "::" must compress at least one group: reject "1:2:3:4:5:6:7:8::".
    if (halves.length === 1 ? missing !== 0 : missing <= 0) return undefined
    const groups = halves.length === 1 ? head : [...head, ...new Array<number>(missing).fill(0), ...tail]
    const out = Buffer.alloc(16)
    groups.forEach((value, index) => out.writeUInt16BE(value, index * 2))
    return out
  } catch {
    return undefined
  }
}

const resolveLocal = (host: string) =>
  Effect.gen(function* () {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host
    const { lookup } = yield* Effect.promise(() => import("node:dns/promises"))
    const addresses = yield* Effect.promise(() => lookup(host, { all: true })).pipe(
      Effect.catch(() => Effect.succeed([] as Array<{ address: string; family: number }>)),
    )
    return addresses.find((item) => item.family === 4)?.address ?? addresses[0]?.address ?? host
  })

const writeThenRead = (socket: import("node:net").Socket, packet: Buffer, count: number) =>
  Effect.gen(function* () {
    yield* Effect.callback<void, LLMError>((resume) => {
      socket.write(packet, (error) => {
        if (error) {
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message: error.message, kind: "proxy" }),
              }),
            ),
          )
          return
        }
        resume(Effect.void)
      })
    })
    return yield* readBytes(socket, count)
  })

const readBytes = (socket: import("node:net").Socket, count: number) =>
  Effect.callback<Buffer, LLMError>((resume, signal) => {
    let buffer = Buffer.alloc(0)
    let done = false
    const finish = (value: Effect.Effect<Buffer, LLMError>) => {
      if (done) return
      done = true
      cleanup()
      resume(value)
    }
    const cleanup = () => {
      signal.removeEventListener("abort", onAbort)
      socket.off("data", onData)
      socket.off("error", onError)
      socket.off("close", onClose)
    }
    const fail = (message: string) =>
      finish(
        Effect.fail(
          new LLMError({
            module: "RequestExecutor",
            method: "execute",
            reason: new TransportReason({ message, kind: "proxy" }),
          }),
        ),
      )
    const onAbort = () => {
      socket.destroy(signal.reason ?? new Error("aborted"))
      fail(signal.reason instanceof Error ? signal.reason.message : "aborted")
    }
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length >= count) {
        const out = buffer.subarray(0, count)
        const extra = buffer.subarray(count)
        // Preserve over-read bytes for the HTTP parser.
        if (extra.length) socket.unshift(extra)
        finish(Effect.succeed(out))
      }
    }
    const onError = (cause: Error) => fail(cause.message)
    const onClose = () => fail("Proxy connection closed")
    if (signal.aborted) {
      onAbort()
      return
    }
    signal.addEventListener("abort", onAbort, { once: true })
    const pending = socket.read()
    if (pending) onData(pending)
    // Re-check after draining the read buffer: over-read bytes were pushed
    // back, so attach the data listener for the remainder.
    if (!done) {
      socket.on("data", onData)
      socket.once("error", onError)
      socket.once("close", onClose)
    }
  })

interface OverSocketRequest {
  method: string
  path: string
  host: string
  headers: Array<[string, string]>
  body: string | Uint8Array | undefined
}

interface OverSocketResponse {
  statusCode: number
  headers: Array<[string, string | undefined]>
  body: AsyncIterable<Uint8Array>
}

const httpOverSocket = (
  socket: import("node:net").Socket,
  request: OverSocketRequest,
): Effect.Effect<OverSocketResponse, LLMError> =>
  Effect.gen(function* () {
    const bodyLength = request.body === undefined ? 0 : Buffer.byteLength(request.body as Uint8Array)
    const lines = [`${request.method} ${request.path} HTTP/1.1`, `Host: ${request.host}`]
    let hasLength = false
    for (const [name, value] of request.headers) {
      const lower = name.toLowerCase()
      // We always buffer the body and frame with Content-Length; forwarding a
      // stale Transfer-Encoding alongside it would create ambiguous framing.
      if (lower === "transfer-encoding") continue
      if (lower === "content-length") hasLength = true
      lines.push(`${name}: ${value}`)
    }
    if (!hasLength) lines.push(`Content-Length: ${bodyLength}`)
    lines.push("Connection: keep-alive", "", "")
    // Abort during socket writes destroys the socket and settles the callback
    // so a cancelled LLM request fails fast instead of hanging until the
    // proxy times out. Resuming after interruption is ignored by the runtime.
    const writeHead = Effect.callback<void, LLMError>((resume, signal) => {
      let settled = false
      const fail = (message: string) => {
        if (settled) return
        settled = true
        signal.removeEventListener("abort", onAbort)
        socket.destroy(signal.reason ?? new Error("aborted"))
        resume(
          Effect.fail(
            new LLMError({
              module: "RequestExecutor",
              method: "execute",
              reason: new TransportReason({ message, kind: "proxy" }),
            }),
          ),
        )
      }
      const onAbort = () => fail(abortMessage(signal))
      if (signal.aborted) {
        fail(abortMessage(signal))
        return
      }
      signal.addEventListener("abort", onAbort, { once: true })
      socket.write(lines.join("\r\n"), (error) => {
        if (settled) return
        settled = true
        signal.removeEventListener("abort", onAbort)
        if (error) {
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message: error.message, kind: "proxy" }),
              }),
            ),
          )
          return
        }
        resume(Effect.void)
      })
    })
    yield* writeHead
    if (request.body !== undefined) {
      const body = request.body
      yield* Effect.callback<void, LLMError>((resume, signal) => {
        let settled = false
        const fail = (message: string) => {
          if (settled) return
          settled = true
          signal.removeEventListener("abort", onAbort)
          socket.destroy(signal.reason ?? new Error("aborted"))
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message, kind: "proxy" }),
              }),
            ),
          )
        }
        const onAbort = () => fail(abortMessage(signal))
        if (signal.aborted) {
          fail(abortMessage(signal))
          return
        }
        signal.addEventListener("abort", onAbort, { once: true })
        socket.write(body as Uint8Array, (error) => {
          if (settled) return
          settled = true
          signal.removeEventListener("abort", onAbort)
          if (error) {
            resume(
              Effect.fail(
                new LLMError({
                  module: "RequestExecutor",
                  method: "execute",
                  reason: new TransportReason({ message: error.message, kind: "proxy" }),
                }),
              ),
            )
            return
          }
          resume(Effect.void)
        })
      })
    }
    const parsed = yield* readHttpHead(socket)
    return {
      statusCode: parsed.statusCode,
      headers: parsed.headers,
      body: httpBodyStream(socket, parsed),
    }
  })

const readHttpHead = (socket: import("node:net").Socket) =>
  Effect.gen(function* () {
    let buffer = Buffer.alloc(0)
    while (true) {
      const chunk: Buffer | undefined = yield* Effect.callback<Buffer | undefined, LLMError>((resume, signal) => {
        let settled = false
        const fail = (message: string) => {
          if (settled) return
          settled = true
          cleanup()
          socket.destroy(signal.reason ?? new Error("aborted"))
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message, kind: "proxy" }),
              }),
            ),
          )
        }
        const onData = (data: Buffer) => {
          if (settled) return
          settled = true
          cleanup()
          resume(Effect.succeed(data))
        }
        const onError = (cause: Error) => {
          if (settled) return
          settled = true
          cleanup()
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message: cause.message, kind: "proxy" }),
              }),
            ),
          )
        }
        const onClose = () => {
          if (settled) return
          settled = true
          cleanup()
          resume(
            Effect.fail(
              new LLMError({
                module: "RequestExecutor",
                method: "execute",
                reason: new TransportReason({ message: "Proxy connection closed", kind: "proxy" }),
              }),
            ),
          )
        }
        const onAbort = () => fail(abortMessage(signal))
        const cleanup = () => {
          signal.removeEventListener("abort", onAbort)
          socket.off("data", onData)
          socket.off("error", onError)
          socket.off("close", onClose)
        }
        if (signal.aborted) {
          fail(abortMessage(signal))
          return
        }
        signal.addEventListener("abort", onAbort, { once: true })
        const pending = socket.read()
        if (pending) {
          if (settled) return
          settled = true
          cleanup()
          resume(Effect.succeed(pending))
          return
        }
        socket.on("data", onData)
        socket.once("error", onError)
        socket.once("close", onClose)
      })
      if (!chunk) {
        return yield* new LLMError({
          module: "RequestExecutor",
          method: "execute",
          reason: new TransportReason({ message: "Proxy connection closed", kind: "proxy" }),
        })
      }
      buffer = Buffer.concat([buffer, chunk])
      const end = buffer.indexOf("\r\n\r\n")
      if (end !== -1) {
        const headText = buffer.subarray(0, end).toString()
        const [statusLine, ...headerLines] = headText.split("\r\n")
        const statusCode = Number(statusLine?.split(" ", 3)[1])
        if (!Number.isFinite(statusCode)) {
          return yield* new LLMError({
            module: "RequestExecutor",
            method: "execute",
            reason: new TransportReason({ message: "Invalid proxy response", kind: "proxy" }),
          })
        }
        const headers = headerLines.map((line) => {
          const index = line.indexOf(":")
          return [line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim()] as [
            string,
            string | undefined,
          ]
        })
        const rest = buffer.subarray(end + 4)
        return { statusCode, headers, rest }
      }
    }
  })

const httpBodyStream = (
  socket: import("node:net").Socket,
  parsed: { headers: Array<[string, string | undefined]>; rest: Buffer },
): AsyncIterable<Uint8Array> => {
  const byName = (name: string) => parsed.headers.find(([key]) => key === name)?.[1]
  const rawLength = Number(byName("content-length"))
  const hasLength = Number.isFinite(rawLength) && rawLength >= 0
  const length = hasLength ? rawLength : undefined
  const chunked = (byName("transfer-encoding") ?? "").toLowerCase().includes("chunked")
  const queue: Array<Uint8Array | undefined> = []
  let waiter: ((chunk: Uint8Array | undefined) => void) | undefined
  // Single accounting point: `remaining` is decremented only in feed() and
  // during rest initialization below — never in the generator drain.
  let remaining = length ?? Number.POSITIVE_INFINITY
  let finished = false
  let bodyError: unknown
  const push = (chunk: Uint8Array | undefined) => {
    if (waiter) {
      const next = waiter
      waiter = undefined
      next(chunk)
      return
    }
    queue.push(chunk)
  }
  const finish = () => {
    if (finished) return
    finished = true
    push(undefined)
  }
  const failBody = (cause: unknown) => {
    if (finished) return
    finished = true
    bodyError = cause
    push(undefined)
  }
  let chunkState: { size: number } | undefined
  let chunkBuffer = Buffer.alloc(0)
  const feed = (data: Buffer) => {
    if (finished) return
    if (!chunked) {
      if (length === undefined) {
        // Close-delimited: no framing, stream until the server closes.
        if (data.length) push(data)
        return
      }
      if (remaining <= 0) {
        finish()
        return
      }
      const take = data.subarray(0, remaining)
      remaining -= take.length
      if (take.length) push(take)
      if (remaining <= 0) finish()
      return
    }
    chunkBuffer = Buffer.concat([chunkBuffer, data])
    while (true) {
      if (!chunkState) {
        const end = chunkBuffer.indexOf("\r\n")
        if (end === -1) return
        const size = Number.parseInt(chunkBuffer.subarray(0, end).toString(), 16)
        if (!Number.isFinite(size)) {
          socket.destroy(new Error("Invalid chunked encoding from proxy"))
          failBody(new Error("Invalid chunked encoding from proxy"))
          return
        }
        chunkBuffer = chunkBuffer.subarray(end + 2)
        if (size === 0) {
          finish()
          return
        }
        chunkState = { size }
      }
      const need = chunkState.size + 2
      if (chunkBuffer.length < need) {
        const take = Math.max(0, chunkBuffer.length - 2)
        if (take > 0) push(chunkBuffer.subarray(0, take))
        chunkState.size -= take
        chunkBuffer = chunkBuffer.subarray(take)
        return
      }
      push(chunkBuffer.subarray(0, chunkState.size))
      chunkBuffer = chunkBuffer.subarray(chunkState.size + 2)
      chunkState = undefined
    }
  }
  // Route the prefetched rest through the same framing path so split
  // Content-Length bodies and chunked bodies are accounted exactly once.
  if (parsed.rest.length) {
    if (chunked) {
      feed(parsed.rest)
    } else if (length !== undefined) {
      const take = parsed.rest.subarray(0, remaining)
      remaining -= take.length
      if (take.length) queue.push(take)
      if (remaining <= 0) finish()
    } else {
      queue.push(parsed.rest)
    }
  } else if (!chunked && length === 0) {
    finish()
  }
  const onData = (data: Buffer) => feed(data)
  const onClose = () => {
    if (finished) return
    // Close-delimited bodies end cleanly here. A close with a positive
    // Content-Length remainder (fixed-length or unfinished chunked) is
    // truncation — surface it instead of ending the stream as success.
    if (length === undefined && !chunked) {
      finish()
      return
    }
    failBody(new Error("Proxy connection closed before the response body completed"))
  }
  const onError = (cause: unknown) => {
    if (finished) return
    failBody(cause instanceof Error ? cause : new Error(String(cause)))
  }
  socket.on("data", onData)
  socket.once("close", onClose)
  socket.once("error", onError)
  return (async function* () {
    try {
      while (true) {
        if (queue.length) {
          const next = queue.shift()
          if (next === undefined) {
            if (bodyError) throw bodyError
            return
          }
          yield next
          continue
        }
        if (finished) {
          if (bodyError) throw bodyError
          return
        }
        const next: Uint8Array | undefined = await new Promise<Uint8Array | undefined>((resolve) => {
          waiter = resolve
        })
        if (next === undefined) {
          if (bodyError) throw bodyError
          return
        }
        yield next
      }
    } finally {
      socket.off("data", onData)
      socket.off("close", onClose)
      socket.off("error", onError)
      // Single-use sockets: lifetime ends with the body. Destroying here (not
      // on headers) keeps split Content-Length bodies alive until the second
      // packet arrives, and still cleans up on abort / early return.
      socket.destroy()
    }
  })()
}

const toClientResponse = (
  response: OverSocketResponse,
  request: HttpClientRequest.HttpClientRequest,
  redactedNames: ReadonlyArray<string | RegExp>,
) =>
  Effect.gen(function* () {
    const headerRecords: Record<string, string> = {}
    for (const [name, value] of response.headers) {
      if (value !== undefined) headerRecords[name] = value
    }
    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => void pump(controller, response.body),
    })
    const web = HttpClientResponse.fromWeb(
      request,
      new Response(stream, { status: response.statusCode, headers: headerRecords }),
    )
    return yield* statusError(request, redactedNames)(web)

    async function pump(
      controller: ReadableStreamDefaultController<Uint8Array>,
      body: AsyncIterable<Uint8Array>,
    ) {
      try {
        for await (const chunk of body) controller.enqueue(chunk)
        controller.close()
      } catch (cause) {
        controller.error(cause)
      }
    }
  })
