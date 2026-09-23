import WebSocket from "ws"
import { createHash } from "node:crypto"
import { ProviderError } from "@/provider/error"
import { isRecord } from "@/util/record"
import { OpenAIWebSocket } from "./ws"

export const TITLE_HEADER = "x-opencode-title"

export interface CreateWebSocketFetchOptions {
  httpFetch?: typeof globalThis.fetch
  url?: string
  connectTimeout?: number
  idleTimeout?: number
  maxConnectionAge?: number
  streamRetries?: number
  // Resolves the session proxy URL for a connect. Receives the request URL
  // (string form of RequestInfo) so resolution honors per-host noProxy rules;
  // may throw on misconfiguration (callers fail fast instead of silently
  // going direct).
  proxy?: (
    sessionID: string | undefined,
    url: string | URL | Request,
  ) => string | undefined | Promise<string | undefined>
}

interface PoolEntry {
  socket?: WebSocket
  connectedAt?: number
  lastUsedAt: number
  busy: boolean
  fallback: boolean
  streamFailures: number
  sessionID: string
  // Redacted proxy label for debugging only — never credentials. The key
  // carries the hash; this field keeps entries attributable.
  proxy: string
}

const DEFAULT_CONNECT_TIMEOUT = 15_000
const DEFAULT_IDLE_TIMEOUT = 5 * 60 * 1000
const DEFAULT_MAX_CONNECTION_AGE = 55 * 60 * 1000
const CONNECTION_LIMIT_REACHED_CODE = "websocket_connection_limit_reached"

export function createWebSocketFetch(options?: CreateWebSocketFetchOptions) {
  const httpFetch = options?.httpFetch ?? globalThis.fetch
  const pool = new Map<string, PoolEntry>()
  const connectTimeout = options?.connectTimeout ?? DEFAULT_CONNECT_TIMEOUT
  const idleTimeout = options?.idleTimeout ?? DEFAULT_IDLE_TIMEOUT
  const maxConnectionAge = options?.maxConnectionAge ?? DEFAULT_MAX_CONNECTION_AGE
  const streamRetries = options?.streamRetries ?? 5
  const pruneTimer = setInterval(() => prune(), Math.min(idleTimeout, 60_000))
  if (typeof pruneTimer === "object" && "unref" in pruneTimer && typeof pruneTimer.unref === "function") {
    pruneTimer.unref()
  }

  // Selections the WS transport already failed, keyed by session plus a hash
  // of the FULL proxy URL and carrying the exact sessionID. The hash (not a
  // redacted label) distinguishes credential rotations: `bot:old@` and
  // `bot:new@` redact identically but must not share entries or verdicts.
  // Consulted after resolution (which must still run per request — see below)
  // but before pool lookup and dialing, so known-bad selections serve HTTP
  // without re-dialing or re-handshaking. Exact session match on removal:
  // prefix matching would confuse `foo` with `foo:bar`.
  const unsupportedSelections = new Map<string, string>()
  const selectionFingerprint = (proxy: string | undefined) =>
    proxy ? createHash("sha256").update(proxy).digest("hex") : "direct"
  const unsupportedKey = (sessionID: string, proxy: string | undefined) =>
    `${sessionID}:${selectionFingerprint(proxy)}`

  async function websocketFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    // Duck-typed: cross-realm URL instances fail `instanceof` but still carry
    // a string `.href`; plain Request objects carry `.url`.
    const url =
      typeof input === "string"
        ? input
        : typeof (input as URL).href === "string"
          ? (input as URL).href
          : (input as Request).url
    const internalHeaders = OpenAIWebSocket.normalizeHeaders(init?.headers)
    const httpInit = withoutInternalHeaders(init)

    if (init?.method !== "POST" || !new URL(url).pathname.endsWith("/responses")) {
      return httpFetch(input, httpInit)
    }

    const body = (() => {
      try {
        if (typeof init?.body !== "string") return undefined
        const parsed = JSON.parse(init.body)
        return typeof parsed === "object" && parsed !== null ? parsed : undefined
      } catch {
        return undefined
      }
    })()
    if (!body?.stream) return httpFetch(input, httpInit)
    if (internalHeaders[TITLE_HEADER] === "true") {
      return httpFetch(input, httpInit)
    }

    const sessionID = internalHeaders["x-session-affinity"] ?? internalHeaders["session-id"]
    // No session affinity (non-streamed POSTs, fallback callers): direct to
    // the wrapped HTTP fetch untouched. Proxy routing lives in the outer
    // provider fetch wrapper — this inner websocketFetch only handles the
    // session-scoped streaming upgrade, so resolving a config default here
    // would double-apply routing and mis-key direct traffic as proxied.
    if (!sessionID) {
      return httpFetch(input, httpInit)
    }
    // Resolve per connect (not per pool entry, and not cached): the pool key
    // embeds the resolution output, so the lookup itself needs it, and
    // caching URLs would go stale on proxy switches or password rotation
    // with no invalidation signal. The two loopback reads are cheap next to
    // a WS handshake. Misconfiguration throws (unknown/disabled proxy)
    // propagate and fail fast; only unusable targets fall back to plain HTTP
    // below, which surfaces its own invalid-URL error.
    let proxy: string | undefined
    try {
      proxy = await options?.proxy?.(sessionID, input)
    } catch (error) {
      if (!OpenAIWebSocket.isInvalidProxyTargetError(error)) throw error
      return httpFetch(input, httpInit)
    }
    // Keys hash the full URL (never the raw credentials, never a redacted
    // label alone): rotations must not reuse sockets authenticated under old
    // secrets, and secrets must not linger in the Map or surface via
    // debugging. Attributability lives on the entry's redacted label.
    const selectionKey = unsupportedKey(sessionID, proxy)
    if (unsupportedSelections.get(selectionKey) === sessionID) {
      return httpFetch(input, httpInit)
    }
    const key = `${selectionKey}:conversation`

    const entry = pool.get(key) ?? {
      lastUsedAt: Date.now(),
      busy: false,
      fallback: false,
      streamFailures: 0,
      sessionID,
      proxy: proxy ? OpenAIWebSocket.redactProxyLabel(proxy) : "direct",
    }
    pool.set(key, entry)

    if (entry.fallback) {
      return httpFetch(input, httpInit)
    }
    if (entry.busy) {
      return httpFetch(input, httpInit)
    }

    entry.busy = true
    entry.lastUsedAt = Date.now()
    try {
      entry.socket = await socket(
        entry,
        options?.url ?? url,
        OpenAIWebSocket.normalizeHeaders(httpInit?.headers),
        connectTimeout,
        maxConnectionAge,
        init?.signal,
        proxy,
      )
      let resolveFirstEvent: (event: boolean | OpenAIWebSocket.WrappedError) => void = () => {}
      let rejectFirstEvent: (error: Error) => void = () => {}
      const firstEvent = new Promise<boolean | OpenAIWebSocket.WrappedError>((resolve, reject) => {
        resolveFirstEvent = resolve
        rejectFirstEvent = reject
      })
      const response = OpenAIWebSocket.streamResponsesWebSocket({
        socket: entry.socket,
        body,
        idleTimeout,
        signal: init?.signal ?? undefined,
        onFirstEvent: (error) => resolveFirstEvent(error ?? true),
        onTerminal: (event) => {
          entry.busy = false
          entry.lastUsedAt = Date.now()
          entry.streamFailures = 0
          if (event.type !== "response.completed" && event.type !== "response.done") {
            invalidate(entry)
          }
        },
        onConnectionInvalid: (_error, closeCode) => {
          entry.busy = false
          entry.lastUsedAt = Date.now()
          if (closeCode === OpenAIWebSocket.MESSAGE_TOO_BIG_CLOSE_CODE) entry.fallback = true
          else if (!entry.fallback) recordStreamFailure(entry)
          invalidate(entry)
          resolveFirstEvent(false)
        },
        onAbort: (error) => {
          entry.busy = false
          entry.lastUsedAt = Date.now()
          entry.streamFailures = 0
          invalidate(entry)
          rejectFirstEvent(error)
        },
        onRetryableTerminal: async (event) => {
          const error = connectionLimitError(event)
          if (!error) return undefined
          throw error
        },
      })
      const first = await firstEvent
      if (first !== false) {
        if (first === true || first.status < 200 || first.status > 599) return response
        return new Response(first.body, {
          status: first.status,
          headers: { "content-type": "application/json", ...first.headers },
        })
      }
      if (!entry.fallback) return response
      return httpFetch(input, httpInit)
    } catch (error) {
      entry.busy = false
      entry.lastUsedAt = Date.now()
      if (OpenAIWebSocket.isAbortError(error)) {
        entry.streamFailures = 0
        invalidate(entry)
        throw error
      }

      // A session proxy the WebSocket transport cannot use is permanent for
      // this selection: skip retries and serve HTTP (itself proxy-routed)
      // on the first failure instead of erroring repeatedly. Recorded both
      // on the entry and in the selection set so later requests skip pool
      // lookup, resolution, and dialing entirely.
      if (OpenAIWebSocket.isProxyUnsupportedError(error)) {
        entry.fallback = true
        unsupportedSelections.set(selectionKey, sessionID)
      }
      recordStreamFailure(entry)
      invalidate(entry)
      if (entry.fallback) return httpFetch(input, httpInit)
      return failedResponse(
        new ProviderError.ResponseStreamError(error instanceof Error ? error.message : String(error), {
          cause: error,
        }),
      )
    }
  }

  function recordStreamFailure(entry: PoolEntry) {
    entry.streamFailures++
    // Codex counts retries after the initial failed WebSocket attempt.
    if (entry.streamFailures > streamRetries) entry.fallback = true
  }

  function prune() {
    const now = Date.now()
    for (const [key, entry] of pool) {
      if (entry.busy) continue
      if (entry.fallback) continue
      if (now - entry.lastUsedAt < idleTimeout) continue
      invalidate(entry)
      pool.delete(key)
    }
  }

  function close() {
    clearInterval(pruneTimer)
    for (const entry of pool.values()) invalidate(entry)
    pool.clear()
    unsupportedSelections.clear()
  }

  function remove(sessionID: string) {
    // Pool keys carry the effective proxy, so one session may own several
    // entries across proxy switches — match on the stored sessionID exactly
    // (never by string prefix, where `foo` would also match `foo:bar`).
    for (const [key, entry] of pool) {
      if (entry.sessionID !== sessionID) continue
      invalidate(entry)
      pool.delete(key)
    }
    for (const [selection, owner] of unsupportedSelections) {
      if (owner === sessionID) unsupportedSelections.delete(selection)
    }
  }

  function has(sessionID: string) {
    for (const entry of pool.values()) {
      if (entry.sessionID === sessionID) return true
    }
    for (const owner of unsupportedSelections.values()) {
      if (owner === sessionID) return true
    }
    return false
  }

  return Object.assign(websocketFetch, { close, remove, has })
}

function connectionLimitError(event: Record<string, unknown>) {
  if (event.type !== "error" || !isRecord(event.error) || event.error.code !== CONNECTION_LIMIT_REACHED_CODE) return
  return new Error(typeof event.error.message === "string" ? event.error.message : CONNECTION_LIMIT_REACHED_CODE)
}

function failedResponse(error: ProviderError.ResponseStreamError) {
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.error(error)
      },
    }),
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  )
}

async function socket(
  entry: PoolEntry,
  url: string,
  headers: Record<string, string>,
  connectTimeout: number,
  maxConnectionAge: number,
  signal?: AbortSignal | null,
  proxy?: string,
) {
  if (
    entry.socket?.readyState === WebSocket.OPEN &&
    entry.connectedAt &&
    Date.now() - entry.connectedAt < maxConnectionAge
  ) {
    return entry.socket
  }

  invalidate(entry)
  const next = await OpenAIWebSocket.connectResponsesWebSocket({
    url: OpenAIWebSocket.toWebSocketUrl(url),
    headers,
    timeout: connectTimeout,
    signal: signal ?? undefined,
    proxy,
  })
  entry.connectedAt = Date.now()
  return next
}

function invalidate(entry: PoolEntry) {
  if (entry.socket) {
    entry.socket.on("error", () => {})
    entry.socket.terminate()
    entry.socket = undefined
  }
  entry.connectedAt = undefined
}

export function withoutInternalHeaders<T extends { headers?: HeadersInit }>(init: T | undefined): T | undefined {
  if (!init?.headers) return init
  if (init.headers instanceof Headers) {
    const headers = new Headers(init.headers)
    headers.delete(TITLE_HEADER)
    return { ...init, headers }
  }

  if (Array.isArray(init.headers)) {
    return { ...init, headers: init.headers.filter((item) => item[0].toLowerCase() !== TITLE_HEADER) }
  }

  return {
    ...init,
    headers: Object.fromEntries(Object.entries(init.headers).filter(([key]) => key.toLowerCase() !== TITLE_HEADER)),
  }
}

export * as OpenAIWebSocketPool from "./ws-pool"
