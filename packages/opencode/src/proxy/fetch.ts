export * as ProxyFetch from "./fetch"

import type { ConfigProxyV1 } from "@opencode-ai/core/v1/config/proxy"
import { Proxy } from "./proxy"
import { IP } from "@/util/ip"

export interface Selection {
  proxyID?: string
  config?: ConfigProxyV1.Info
}

// Redacted selection key for the per-provider SDK cache. Sessions sharing a
// selection share one SDK instance; per-request routing still resolves per URL.
export function key(selection: Selection) {
  return selection.proxyID ?? selection.config?.default ?? Proxy.SYSTEM
}

export interface Pool {
  sockets: Map<string, SocketPool>
}

export function createPool(): Pool {
  return { sockets: new Map() }
}

type Routed = Extract<Proxy.Resolved, { kind: "env" | "proxy" }>

// Returns a proxied fetch for the request, or undefined when the request
// resolves to direct (caller falls through to the existing fetch path).
export function fetch(
  pool: Pool,
  selection: Selection,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> | undefined {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
  const resolved = Proxy.resolveForSession({ proxyID: selection.proxyID, proxy: selection.config, url })
  if (resolved.kind === "direct") return undefined
  return send(pool, resolved, input, init)
}

async function send(
  pool: Pool,
  resolved: Routed,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
  const target = new URL(href)
  const headers = new Headers(init?.headers)
  headers.delete("host")
  // Timeouts stay owned by the caller's AbortSignal (the provider fetch
  // wrapper governs chunk/header timeouts); no inactivity timeouts are
  // applied here so long-lived SSE streams survive.
  const result = await dispatchThroughProxy(pool, resolved, {
    target,
    method: init?.method ?? "GET",
    headers,
    body: await bufferBody(init?.body),
    signal: init?.signal ?? undefined,
  })
  const responseHeaders = new Headers()
  for (const [name, value] of result.headers) {
    if (value !== undefined) responseHeaders.append(name, value)
  }
  return new Response(nodeToWeb(result.body, result.onClose), {
    status: result.statusCode,
    headers: responseHeaders,
  })
}

function nodeToWeb(body: AsyncIterable<Uint8Array>, onClose?: () => void) {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        for await (const chunk of body) controller.enqueue(chunk)
        controller.close()
      } catch (cause) {
        controller.error(cause)
      } finally {
        onClose?.()
      }
    },
    async cancel() {
      const stream = body as AsyncIterable<Uint8Array> & { destroy?: () => void }
      stream.destroy?.()
      onClose?.()
    },
  })
}

interface ProxyRequest {
  target: URL
  method: string
  headers: Headers
  body: string | Uint8Array | undefined
  signal: AbortSignal | undefined
}

interface ProxyResult {
  statusCode: number
  headers: Array<[string, string | undefined]>
  body: AsyncIterable<Uint8Array>
  onClose?: () => void
  /** True only when the body framing completed with no surplus bytes and no
   * errors, so a pooled socket can safely serve the next request. */
  reusable: () => boolean
}

async function bufferBody(body: BodyInit | null | undefined) {
  if (body === undefined || body === null) return undefined
  if (typeof body === "string") return body
  if (body instanceof Uint8Array) return body
  if (body instanceof ArrayBuffer) return new Uint8Array(body)
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
  }
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer())
  if (body instanceof FormData || body instanceof URLSearchParams) return body.toString()
  if (typeof (body as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function") {
    const chunks: Uint8Array[] = []
    for await (const chunk of body as unknown as AsyncIterable<Uint8Array>) chunks.push(chunk)
    return Buffer.concat(chunks)
  }
  throw new Error("Unsupported proxied request body")
}

function schemeOf(resolved: Routed) {
  if (resolved.kind === "proxy") return resolved.entry.type
  const protocol = resolved.url.split(":", 1)[0]?.toLowerCase()
  if (protocol === "socks4" || protocol === "socks5" || protocol === "socks5h") return protocol
  return protocol === "https" ? "https" : "http"
}

interface SocketPool {
  idle: import("node:net").Socket[]
}

function poolFor(pool: Pool, resolved: Routed) {
  const cacheKey = `${resolved.url}\0${schemeOf(resolved)}`
  const existing = pool.sockets.get(cacheKey)
  if (existing) return existing
  const created: SocketPool = { idle: [] }
  pool.sockets.set(cacheKey, created)
  return created
}

async function dispatchThroughProxy(
  pool: Pool,
  resolved: Routed,
  request: ProxyRequest,
): Promise<ProxyResult> {
  const scheme = schemeOf(resolved)
  if (scheme === "http" || scheme === "https") return dispatchHttp(pool, resolved, request)
  return dispatchSocks(pool, resolved, request, scheme === "socks5h")
}

function proxyAuth(resolved: Routed) {
  const proxy = new URL(resolved.url)
  if (!proxy.username && !proxy.password) return undefined
  return `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}`
}

// Plain-HTTP targets are forwarded absolute-form; HTTPS targets go through a
// CONNECT tunnel with TLS to the target over the tunnel socket.
// Proxy-Authorization stays on the proxy leg only (CONNECT / forward) and is
// never forwarded inside the TLS tunnel to the origin.
async function dispatchHttp(pool: Pool, resolved: Routed, request: ProxyRequest): Promise<ProxyResult> {
  const pooled = poolFor(pool, resolved)
  const proxy = new URL(resolved.url)
  const auth = proxyAuth(resolved)
  const baseHeaders: Array<[string, string]> = []
  request.headers.forEach((value, name) => {
    if (name.toLowerCase() === "proxy-authorization") return
    baseHeaders.push([name, value])
  })

  // A pooled socket can die between validation and use (server idle-timeout
  // FIN in flight): retry once on a fresh connection before surfacing. Abort
  // is never retried; auth/TLS failures surface after the single retry.
  if (request.target.protocol === "https:") {
    try {
      const socket = await pooledSocket(pooled, proxy, request.signal)
      const tunnel = await connectTunnel(socket, pooled, proxy, request.target, auth, request.signal)
      return await requestOverTunnel(tunnel, request, baseHeaders)
    } catch (cause) {
      if (request.signal?.aborted) throw cause
      const socket = await pooledSocket(pooled, proxy, request.signal, true)
      const tunnel = await connectTunnel(socket, pooled, proxy, request.target, auth, request.signal)
      return await requestOverTunnel(tunnel, request, baseHeaders)
    }
  }
  const headers = auth ? [...baseHeaders, ["proxy-authorization", auth] as [string, string]] : baseHeaders
  try {
    const socket = await pooledSocket(pooled, proxy, request.signal)
    return await requestOverSocket(socket, pooled, request.target.href, request, headers)
  } catch (cause) {
    if (request.signal?.aborted) throw cause
    const socket = await pooledSocket(pooled, proxy, request.signal, true)
    return await requestOverSocket(socket, pooled, request.target.href, request, headers)
  }
}

async function pooledSocket(
  pooled: SocketPool,
  proxy: URL,
  signal: AbortSignal | undefined,
  fresh = false,
): Promise<import("node:net").Socket> {
  if (!fresh) {
    const idle = pooled.idle.pop()
    if (idle) {
      // A server-closed idle connection can still pass destroyed/writable
      // (FIN received while still writable, or buffered framing bytes), and
      // the next head parse would fail on it — only hand out live sockets.
      if (!idle.destroyed && idle.writable && idle.readable && !idle.readableEnded && idle.readableLength === 0)
        return idle
      idle.destroy()
    }
  }
  const { connect } = await import("node:net")
  // An `https:` proxy URL demands TLS to the proxy itself; without the wrap
  // below, CONNECT + Proxy-Authorization would travel in cleartext.
  const defaultPort = proxy.protocol === "https:" ? 443 : 80
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("aborted"))
      return
    }
    const socket = connect({ host: proxy.hostname, port: Number(proxy.port) || defaultPort })
    const onAbort = () => {
      socket.destroy(signal?.reason ?? new Error("aborted"))
      reject(signal?.reason ?? new Error("aborted"))
    }
    signal?.addEventListener("abort", onAbort, { once: true })
    socket.once("error", (cause) => {
      signal?.removeEventListener("abort", onAbort)
      reject(cause)
    })
    socket.once("connect", () => {
      signal?.removeEventListener("abort", onAbort)
      if (proxy.protocol !== "https:") {
        resolve(socket)
        return
      }
      secureProxySocket(socket, proxy, signal).then(resolve, reject)
    })
  })
}

// SNI must not carry IP literals (rejected outright, and forbidden by
// RFC 6066), so proven literals omit it. Calibration showed the default
// verification path still checks IP SANs (accepts the right cert, rejects a
// wrong-name cert), while the exported checkServerIdentity mishandles IP
// SANs — so IP literals rely on defaults and DNS names use `servername`.
const tlsServerOptions = (hostname: string) => (IP.isIPLiteral(hostname) ? {} : { servername: hostname })

// TLS-wrap an already-connected proxy socket and wait for the handshake, so
// CONNECT bytes are never written pre-handshake and proxy certificate
// verification failures surface instead of hanging or leaking cleartext.
function secureProxySocket(
  socket: import("node:net").Socket,
  proxy: URL,
  signal: AbortSignal | undefined,
): Promise<import("node:net").Socket> {
  return new Promise((resolve, reject) => {
    // NOTE: tls.connect({ socket }) — not `new TLSSocket(socket)` — is the
    // documented STARTTLS-client API; direct construction stalls the
    // handshake on calibration (verified against node 22 + Bun).
    void import("node:tls").then(({ connect: tlsConnect }) => {
      let tls: import("node:tls").TLSSocket | undefined
      let settled = false
      const fail = (cause: unknown) => {
        if (settled) return
        settled = true
        cleanup()
        socket.destroy()
        tls?.destroy()
        reject(cause)
      }
      const cleanup = () => {
        signal?.removeEventListener("abort", onAbort)
        tls?.off("secureConnect", onSecure)
        tls?.off("error", onTlsError)
        tls?.off("close", onTlsClose)
      }
      const onAbort = () => fail(signal?.reason ?? new Error("aborted"))
      const onTlsError = (cause: Error) => fail(cause)
      // A TCP close mid-handshake emits no error — without this the wrap
      // would hang instead of failing.
      const onTlsClose = () => fail(new Error("TLS connection closed during handshake"))
      const onSecure = () => {
        if (settled) return
        settled = true
        cleanup()
        resolve(tls as unknown as import("node:net").Socket)
      }
      if (signal?.aborted) {
        fail(signal.reason ?? new Error("aborted"))
        return
      }
      signal?.addEventListener("abort", onAbort, { once: true })
      try {
        tls = tlsConnect({
          socket,
          ALPNProtocols: ["http/1.1"],
          ...tlsServerOptions(proxy.hostname),
        })
        if (!tls) throw new Error("TLS socket creation returned undefined")
      } catch (cause) {
        fail(cause)
        return
      }
      tls.once("secureConnect", onSecure)
      tls.once("error", onTlsError)
      tls.once("close", onTlsClose)
    }, reject)
  })
}

function releaseSocket(pooled: SocketPool, socket: import("node:net").Socket) {
  if (socket.destroyed || !socket.writable) return
  socket.removeAllListeners("error")
  socket.once("error", () => {})
  pooled.idle.push(socket)
}

async function connectTunnel(
  socket: import("node:net").Socket,
  pooled: SocketPool,
  proxy: URL,
  target: URL,
  auth: string | undefined,
  signal: AbortSignal | undefined,
) {
  const { connect: tlsConnect } = await import("node:tls")
  const port = Number(target.port) || 443
  void pooled
  void proxy
  return new Promise<import("node:net").Socket>((resolve, reject) => {
    const lines = [`CONNECT ${target.hostname}:${port} HTTP/1.1`, `Host: ${target.hostname}:${port}`]
    if (auth) lines.push(`Proxy-Authorization: ${auth}`)
    lines.push("Proxy-Connection: Keep-Alive", "", "")
    let head = Buffer.alloc(0)
    let tls: import("node:tls").TLSSocket | undefined
    let settled = false
    const fail = (cause: unknown) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      tls?.destroy()
      reject(cause)
    }
    const cleanup = () => {
      signal?.removeEventListener("abort", onAbort)
      socket.off("data", onData)
      socket.off("error", onSocketError)
      socket.off("close", onClose)
      tls?.off("secureConnect", onSecure)
      tls?.off("error", onTlsError)
      tls?.off("close", onTlsClose)
    }
    if (signal?.aborted) {
      fail(signal.reason ?? new Error("aborted"))
      return
    }
    const onAbort = () => fail(signal?.reason ?? new Error("aborted"))
    const onSocketError = (cause: unknown) => {
      if (!tls) fail(cause)
    }
    const onClose = () => {
      if (!tls) fail(new Error("Proxy connection closed during CONNECT"))
    }
    const onTlsError = (cause: Error) => fail(cause)
    const onTlsClose = () => fail(new Error("TLS connection closed during handshake"))
    const onSecure = () => {
      if (settled) return
      settled = true
      cleanup()
      resolve(tls as unknown as import("node:net").Socket)
    }
    signal?.addEventListener("abort", onAbort, { once: true })
    socket.once("error", onSocketError)
    socket.once("close", onClose)
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk])
      const end = head.indexOf("\r\n\r\n")
      if (end === -1) return
      socket.off("data", onData)
      socket.off("error", onSocketError)
      socket.off("close", onClose)
      const status = Number(head.subarray(0, end).toString().split("\r\n", 1)[0]?.split(" ", 3)[1])
      if (status !== 200) {
        fail(new Error(`Proxy CONNECT failed with status ${status}`))
        return
      }
      const rest = head.subarray(end + 4)
      try {
        tls = tlsConnect({
          socket,
          ALPNProtocols: ["http/1.1"],
          ...tlsServerOptions(target.hostname),
        })
        if (!tls) throw new Error("TLS socket creation returned undefined")
      } catch (cause) {
        fail(cause)
        return
      }
      if (rest.length) tls.unshift(rest)
      // Wait for the handshake so HTTP is never written pre-handshake and
      // certificate verification failures surface as TLS errors.
      tls.once("secureConnect", onSecure)
      tls.once("error", onTlsError)
      tls.once("close", onTlsClose)
    }
    socket.on("data", onData)
    socket.write(lines.join("\r\n"))
  })
}

async function requestOverTunnel(
  tunnel: import("node:net").Socket,
  request: ProxyRequest,
  headers: Array<[string, string]>,
): Promise<ProxyResult> {
  const path = `${request.target.pathname}${request.target.search}`
  // Defense-in-depth: Proxy-Authorization must never travel inside the TLS
  // tunnel to the origin, even if a caller mistakenly included it.
  const inner = headers.filter(([name]) => name.toLowerCase() !== "proxy-authorization")
  const response = await httpOverSocket(tunnel, {
    method: request.method,
    path,
    host: request.target.host,
    headers: inner,
    body: request.body,
    signal: request.signal,
  })
  // The tunnel socket is single-use for this request; destroy after the body.
  const body = response.body
  return { ...response, onClose: () => tunnel.destroy() }
}

async function requestOverSocket(
  socket: import("node:net").Socket,
  pooled: SocketPool,
  path: string,
  request: ProxyRequest,
  headers: Array<[string, string]>,
): Promise<ProxyResult> {
  const response = await httpOverSocket(socket, {
    method: request.method,
    path,
    host: new URL(path).host,
    headers,
    body: request.body,
    signal: request.signal,
  })
  // Keep-alive: pool the socket only after the body was fully and cleanly
  // consumed. Early cancel, errors, truncation, or surplus framing bytes mean
  // the next response head would be read from the previous body tail, so the
  // socket must be destroyed instead.
  let completed = false
  let settled = false
  const settle = () => {
    if (settled) return
    settled = true
    if (completed && response.reusable()) releaseSocket(pooled, socket)
    else socket.destroy()
  }
  const tracked = (async function* () {
    try {
      yield* response.body
      completed = true
    } finally {
      settle()
    }
  })()
  return { ...response, body: tracked, onClose: settle }
}

interface SocketHttpRequest {
  method: string
  path: string
  host: string
  headers: Array<[string, string]>
  body: string | Uint8Array | undefined
  signal: AbortSignal | undefined
}

async function httpOverSocket(
  socket: import("node:net").Socket,
  request: SocketHttpRequest,
): Promise<ProxyResult> {
  return new Promise((resolve, reject) => {
    if (request.signal?.aborted) {
      reject(request.signal.reason ?? new Error("aborted"))
      return
    }
    const bodyLength = request.body === undefined ? 0 : Buffer.byteLength(request.body as Uint8Array)
    const lines = [`${request.method} ${request.path} HTTP/1.1`, `Host: ${request.host}`]
    let hasLength = false
    for (const [name, value] of request.headers) {
      const lower = name.toLowerCase()
      // We buffer the body and frame with Content-Length; forwarding a stale
      // Transfer-Encoding alongside it would create ambiguous framing.
      if (lower === "transfer-encoding") continue
      if (lower === "content-length") hasLength = true
      lines.push(`${name}: ${value}`)
    }
    if (!hasLength) lines.push(`Content-Length: ${bodyLength}`)
    lines.push("Connection: keep-alive", "", "")
    const head = lines.join("\r\n")

    const chunks: Buffer[] = []
    let headerEnd = -1
    let statusCode = 0
    let responseHeaders: Array<[string, string | undefined]> = []
    let remaining = 0
    let chunked = false
    let settled = false
    // Framing integrity for pooled reuse: cleanEnd marks a terminal frame,
    // surplus marks bytes beyond framing that would corrupt the next response.
    let cleanEnd = false
    let surplus = false
    const reusable = () =>
      cleanEnd && !surplus && !bodyError && !socket.destroyed && socket.writable

    const fail = (cause: unknown) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(cause)
    }
    const onAbort = () => fail(request.signal?.reason ?? new Error("aborted"))
    request.signal?.addEventListener("abort", onAbort, { once: true })

    // Pull-based body queue fed by the socket data handler.
    const queue: Array<Uint8Array | undefined> = []
    let waiter: ((chunk: Uint8Array | undefined) => void) | undefined
    let bodyDone = false
    let bodyError: unknown
    const nextBodyChunk = () =>
      new Promise<Uint8Array | undefined>((next) => {
        if (queue.length) {
          next(queue.shift())
          return
        }
        if (bodyDone) {
          next(undefined)
          return
        }
        if (bodyError) throw bodyError
        waiter = next
      })
    const pushBody = (chunk: Uint8Array | undefined) => {
      if (waiter) {
        const next = waiter
        waiter = undefined
        next(chunk)
        return
      }
      queue.push(chunk)
    }

    const onBodyData = (data: Buffer) => feedBody(data)
    const cleanup = () => {
      request.signal?.removeEventListener("abort", onAbort)
      socket.off("data", onData)
      socket.off("data", onBodyData)
      socket.off("error", onError)
      socket.off("close", onClose)
    }

    const bodyStream = (async function* () {
      try {
        while (true) {
          const chunk = await nextBodyChunk()
          if (chunk === undefined) {
            if (bodyError) throw bodyError
            return
          }
          yield chunk
        }
      } finally {
        cleanup()
      }
    })()
    const onError = (cause: unknown) => {
      if (bodyDone) {
        fail(cause)
        return
      }
      bodyError = cause
      bodyDone = true
      // After headers the head promise already settled, so fail() is a no-op —
      // destroy explicitly so a corrupt pooled socket is never reused.
      if (headerEnd !== -1) socket.destroy()
      waiter?.(undefined)
      if (queue.length === 0 || queue[queue.length - 1] !== undefined) queue.push(undefined)
      fail(cause)
    }
    const onClose = () => {
      if (headerEnd === -1) {
        if (!settled) onError(new Error("Proxy connection closed"))
        return
      }
      if (bodyDone) return
      // Close-delimited bodies end cleanly here. A close with a positive
      // Content-Length remainder (or unfinished chunked) is truncation.
      if (!chunked && remaining === Number.POSITIVE_INFINITY) {
        bodyDone = true
        cleanEnd = true
        pushBody(undefined)
        return
      }
      onError(new Error("Proxy connection closed before the response body completed"))
    }
    const onData = (data: Buffer) => {
      chunks.push(data)
      if (headerEnd === -1) {
        const joined = Buffer.concat(chunks)
        const end = joined.indexOf("\r\n\r\n")
        if (end === -1) return
        headerEnd = end
        const headText = joined.subarray(0, end).toString()
        const [statusLine, ...headerLines] = headText.split("\r\n")
        statusCode = Number(statusLine?.split(" ", 3)[1])
        if (!Number.isFinite(statusCode)) {
          fail(new Error("Invalid proxy response"))
          return
        }
        responseHeaders = headerLines.map((line) => {
          const index = line.indexOf(":")
          return [line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim()] as [
            string,
            string | undefined,
          ]
        })
        const byName = (name: string) => responseHeaders.find(([key]) => key === name)?.[1]
        const rawLength = Number(byName("content-length"))
        const hasLength = Number.isFinite(rawLength) && rawLength >= 0
        remaining = hasLength ? rawLength : Number.POSITIVE_INFINITY
        chunked = (byName("transfer-encoding") ?? "").toLowerCase().includes("chunked")
        if (!settled) {
          settled = true
          cleanupSocketListeners()
          resolve({ statusCode, headers: responseHeaders, body: bodyStream, reusable })
        }
        const rest = joined.subarray(end + 4)
        if (rest.length) feedBody(rest)
        else if (!chunked && remaining === 0) {
          // Empty fixed-length body with no bytes on the wire: end cleanly
          // instead of waiting for data that will never arrive.
          bodyDone = true
          cleanEnd = true
          pushBody(undefined)
        }
        return
      }
      feedBody(data)
    }

    // After headers resolve, socket events feed the body only.
    const cleanupSocketListeners = () => {
      socket.off("data", onData)
      socket.on("data", onBodyData)
    }

    let chunkState: { size: number; received: number } | undefined
    let chunkBuffer = Buffer.alloc(0)
    let awaitingFinalCrlf = false
    const endBodyClean = () => {
      bodyDone = true
      cleanEnd = true
      pushBody(undefined)
    }
    const feedBody = (data: Buffer) => {
      // Bytes after a terminal frame mean framing misaligned with the socket:
      // end the stream and never pool.
      if (bodyDone) {
        if (data.length) surplus = true
        return
      }
      if (!chunked) {
        if (remaining === Number.POSITIVE_INFINITY) {
          // Close-delimited: no Content-Length, stream until close.
          if (data.length) pushBody(data)
          return
        }
        if (remaining <= 0) {
          // No body (or fully read): end stream; extra bytes can't be reframed.
          if (data.length) surplus = true
          endBodyClean()
          return
        }
        const take = data.subarray(0, remaining)
        remaining -= take.length
        if (data.length > take.length) surplus = true
        if (take.length) pushBody(take)
        if (remaining <= 0) endBodyClean()
        return
      }
      // Chunked terminal split across packets: consume the final CRLF before
      // ending so pooled reuse starts at a clean frame boundary.
      if (awaitingFinalCrlf) {
        chunkBuffer = Buffer.concat([chunkBuffer, data])
        if (chunkBuffer.length < 2) return
        if (chunkBuffer[0] === 0x0d && chunkBuffer[1] === 0x0a) {
          if (chunkBuffer.length > 2) surplus = true
        } else {
          // Trailers or garbage: body is complete but reframing is unsafe.
          surplus = true
        }
        awaitingFinalCrlf = false
        chunkBuffer = Buffer.alloc(0)
        endBodyClean()
        return
      }
      chunkBuffer = Buffer.concat([chunkBuffer, data])
      while (true) {
        if (!chunkState) {
          const end = chunkBuffer.indexOf("\r\n")
          if (end === -1) return
          const size = Number.parseInt(chunkBuffer.subarray(0, end).toString(), 16)
          if (!Number.isFinite(size)) {
            onError(new Error("Invalid chunked encoding from proxy"))
            return
          }
          chunkBuffer = chunkBuffer.subarray(end + 2)
          if (size === 0) {
            if (chunkBuffer.length === 0 || chunkBuffer.length === 1) {
              // Terminal CRLF split across packets: wait for the rest.
              awaitingFinalCrlf = true
              return
            }
            if (chunkBuffer[0] === 0x0d && chunkBuffer[1] === 0x0a) {
              if (chunkBuffer.length > 2) surplus = true
              chunkBuffer = Buffer.alloc(0)
              endBodyClean()
              return
            }
            // Trailers: body complete but the socket can't be reframed.
            surplus = true
            chunkBuffer = Buffer.alloc(0)
            endBodyClean()
            return
          }
          chunkState = { size, received: 0 }
        }
        const need = chunkState.size - chunkState.received + 2
        if (chunkBuffer.length < need) {
          pushBody(chunkBuffer.subarray(0, chunkBuffer.length - Math.min(2, chunkBuffer.length)))
          chunkState.received += Math.max(0, chunkBuffer.length - 2)
          chunkBuffer = Buffer.alloc(0)
          return
        }
        const piece = chunkBuffer.subarray(0, chunkState.size - chunkState.received)
        pushBody(piece)
        chunkBuffer = chunkBuffer.subarray(chunkState.size - chunkState.received + 2)
        chunkState = undefined
      }
    }

    socket.on("data", onData)
    socket.once("error", onError)
    socket.once("close", onClose)
    socket.write(head)
    if (request.body !== undefined) socket.write(request.body as Uint8Array)
  })
}

// SOCKS dial via the socks package. socks5h keeps the hostname for remote
// DNS; socks4/socks5 resolve locally first.
async function dispatchSocks(
  pool: Pool,
  resolved: Routed,
  request: ProxyRequest,
  remoteDNS: boolean,
): Promise<ProxyResult> {
  const proxy = new URL(resolved.url)
  const rawType = schemeOf(resolved)
  const pooled = poolFor(pool, resolved)
  void pooled
  const cacheKey = resolved.url
  const dialKey = `${cacheKey}\0dial`
  const existing = pool.sockets.get(dialKey)
  const dial = existing
    ? ((existing as unknown as { __dial: SocksDial }).__dial as SocksDial)
    : await createSocksDial({
        host: proxy.hostname,
        port: Number(proxy.port) || 1080,
        type: rawType === "socks4" ? 4 : 5,
        // Config entries carry the username separately; env URLs carry it in
        // userinfo. Reading only the password from the URL would send
        // password-without-username and fail SOCKS auth for env proxies.
        userId:
          resolved.kind === "proxy"
            ? resolved.entry.username
            : proxy.username
              ? decodeURIComponent(proxy.username)
              : undefined,
        password: proxy.password ? decodeURIComponent(proxy.password) : undefined,
        remoteDNS,
      })
  if (!existing) {
    const holder = { idle: [] as import("node:net").Socket[], __dial: dial }
    pool.sockets.set(dialKey, holder as unknown as SocketPool)
  }
  if (request.signal?.aborted) throw request.signal.reason ?? new Error("aborted")
  const targetPort = Number(request.target.port) || (request.target.protocol === "https:" ? 443 : 80)
  const socket = await dial(request.target.hostname, targetPort)
  if (request.signal?.aborted) {
    socket.destroy(request.signal.reason ?? new Error("aborted"))
    throw request.signal.reason ?? new Error("aborted")
  }
  // SOCKS auth travels in the handshake, never as Proxy-Authorization to the
  // origin. Forward the caller's headers (minus any proxy credentials).
  const headers: Array<[string, string]> = []
  request.headers.forEach((value, name) => {
    if (name.toLowerCase() === "proxy-authorization") return
    headers.push([name, value])
  })
  if (request.target.protocol === "https:") {
    // TLS to the target over the SOCKS socket; wait for the handshake so
    // cert errors surface and HTTP is never written pre-handshake.
    const { connect: tlsConnect } = await import("node:tls")
    const tls = await new Promise<import("node:net").Socket>((resolve, reject) => {
      let tlsSocket: import("node:tls").TLSSocket | undefined
      let settled = false
      const fail = (cause: unknown) => {
        if (settled) return
        settled = true
        cleanup()
        socket.destroy()
        tlsSocket?.destroy()
        reject(cause)
      }
      const cleanup = () => {
        request.signal?.removeEventListener("abort", onAbort)
        tlsSocket?.off("secureConnect", onSecure)
        tlsSocket?.off("error", onTlsError)
        tlsSocket?.off("close", onTlsClose)
      }
      const onAbort = () => fail(request.signal?.reason ?? new Error("aborted"))
      const onTlsError = (cause: Error) => fail(cause)
      const onTlsClose = () => fail(new Error("TLS connection closed during handshake"))
      const onSecure = () => {
        if (settled) return
        settled = true
        cleanup()
        resolve(tlsSocket as unknown as import("node:net").Socket)
      }
      if (request.signal?.aborted) {
        fail(request.signal.reason ?? new Error("aborted"))
        return
      }
      request.signal?.addEventListener("abort", onAbort, { once: true })
      try {
        tlsSocket = tlsConnect({
          socket,
          ALPNProtocols: ["http/1.1"],
          ...tlsServerOptions(request.target.hostname),
        })
        if (!tlsSocket) throw new Error("TLS socket creation returned undefined")
      } catch (cause) {
        fail(cause)
        return
      }
      tlsSocket.once("secureConnect", onSecure)
      tlsSocket.once("error", onTlsError)
      tlsSocket.once("close", onTlsClose)
    })
    return requestOverTunnel(tls, request, headers)
  }
  return requestOverSocket(socket, poolFor(pool, resolved), request.target.href, request, headers)
}

interface SocksDial {
  (host: string, port: number): Promise<import("node:net").Socket>
}

interface SocksEndpoint {
  host: string
  port: number
  type: 4 | 5
  userId?: string
  password?: string
  remoteDNS: boolean
}

async function createSocksDial(endpoint: SocksEndpoint): Promise<SocksDial> {
  const { SocksClient } = await import("socks")
  return async (host, port) => {
    const destination = endpoint.remoteDNS ? host : await lookup(host)
    const connection = await SocksClient.createConnection({
      proxy: {
        host: endpoint.host,
        port: endpoint.port,
        type: endpoint.type,
        ...(endpoint.userId ? { userId: endpoint.userId } : {}),
        ...(endpoint.password ? { password: endpoint.password } : {}),
      },
      destination: { host: destination, port },
      command: "connect",
    })
    return connection.socket
  }
}

async function lookup(host: string) {
  const { lookup } = await import("node:dns/promises")
  const addresses = await lookup(host, { all: true })
  const pick = (family: number) => addresses.find((address) => address.family === family)?.address
  return pick(4) ?? pick(6) ?? host
}
