// Low-level OpenAI Responses WebSocket protocol helpers. Session pooling,
// fallback, and continuation state intentionally live above this file.

import WebSocket from "ws"
import { APICallError } from "ai"
import { ProviderError } from "@/provider/error"
import { errorMessage } from "@/util/error"
import { ProxyEnv } from "@/util/proxy-env"
import { isRecord } from "@/util/record"

export const PROTOCOL_HEADER = "responses_websockets=2026-02-06"
export const MESSAGE_TOO_BIG_CLOSE_CODE = 1009

export interface ConnectResponsesWebSocketOptions {
  url: string
  headers: Record<string, string>
  timeout?: number
  signal?: AbortSignal
  proxy?: string
}

export interface StreamResponsesWebSocketOptions {
  socket: WebSocket
  body: Record<string, unknown>
  idleTimeout?: number
  signal?: AbortSignal
  onFirstEvent?: (error?: WrappedError) => void
  onComplete?: (event: Record<string, unknown>) => void
  onTerminal?: (event: Record<string, unknown>) => void
  onRetryableTerminal?: (event: Record<string, unknown>) => Promise<WebSocket | undefined>
  onConnectionInvalid?: (error: ProviderError.ResponseStreamError, closeCode?: number) => void
  onAbort?: (error: Error) => void
}

export interface WrappedError {
  status: number
  headers?: Record<string, string>
  body: string
}

export function toWebSocketUrl(url: string) {
  return url.replace(/^http/, "ws")
}

export function normalizeHeaders(headers: HeadersInit | undefined): Record<string, string> {
  const result: Record<string, string> = {}
  if (!headers) return result

  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      result[key.toLowerCase()] = value
    })
    return result
  }

  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      result[key.toLowerCase()] = value
    }
    return result
  }

  for (const [key, value] of Object.entries(headers)) {
    if (value != null) result[key.toLowerCase()] = value
  }
  return result
}

export function isAbortError(error: unknown): error is DOMException {
  return error instanceof DOMException && error.name === "AbortError"
}

export function connectWithProxyAuth(headers: Record<string, string>, proxy: string | undefined) {
  if (!proxy || !URL.canParse(proxy)) return { headers, ...(proxy ? { proxy } : {}) }
  const parsed = new URL(proxy)
  if (!parsed.username && !parsed.password) return { headers, proxy }
  const auth = `Basic ${Buffer.from(`${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`).toString("base64")}`
  parsed.username = ""
  parsed.password = ""
  return { headers: { ...headers, "proxy-authorization": auth }, proxy: parsed.toString() }
}

export function connectResponsesWebSocket(options: ConnectResponsesWebSocketOptions) {
  return new Promise<WebSocket>((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(abortError(options.signal))
      return
    }

    const headers: Record<string, string> = {
      ...options.headers,
      "openai-beta": options.headers["openai-beta"] ?? PROTOCOL_HEADER,
    }
    delete headers["content-length"]

    // Bun does not apply HTTP(S)_PROXY to WebSockets unless the proxy is supplied explicitly.
    // An explicit session proxy wins over the environment. The ws client only
    // tunnels CONNECT through http(s) proxies, so an explicit SOCKS session
    // proxy rejects here — a session pinned to SOCKS must not silently route
    // direct or via an HTTP env proxy while the HTTP path uses SOCKS.
    // Parse the scheme case-insensitively so SOCKS5:// or padded values can't
    // slip through to the CONNECT path. Trim once and reuse the trimmed value
    // so a padded proxy never reaches the dial with whitespace intact.
    const trimmedProxy = options.proxy?.trim() || undefined
    const proxyScheme = (() => {
      const value = trimmedProxy ?? ""
      const separator = value.indexOf("://")
      if (separator === -1) return value.toLowerCase()
      return value.slice(0, separator).toLowerCase()
    })()
    const explicitSocks = trimmedProxy && proxyScheme.startsWith("socks") ? trimmedProxy : undefined
    // The ws client cannot tunnel SOCKS. Failing closed here: falling back to
    // direct would silently bypass the session proxy while the HTTP path uses
    // it, and falling back to env could route via an unrelated HTTP proxy.
    if (explicitSocks) {
      reject(
        new Error(
          `Session SOCKS proxy "${explicitSocks}" is not supported for WebSockets; use an HTTP(S) proxy or direct.`,
        ),
      )
      return
    }
    const explicit = trimmedProxy
    const proxy =
      explicit ??
      (typeof Bun === "undefined"
        ? undefined
        : ProxyEnv.getProxyForUrl(options.url.replace(/^wss:/, "https:").replace(/^ws:/, "http:")))
    // The ws package tunnels CONNECT itself; strip userinfo into an explicit
    // Proxy-Authorization header so credentials are always forwarded.
    const connect = connectWithProxyAuth(headers, proxy)
    const socket = new WebSocket(options.url, connect)
    const timeout = options.timeout
      ? setTimeout(() => {
          cleanup()
          socket.on("error", () => {})
          socket.terminate()
          reject(new Error("WebSocket connect timed out"))
        }, options.timeout)
      : undefined

    function cleanup() {
      if (timeout) clearTimeout(timeout)
      socket.off("open", onOpen)
      socket.off("error", onError)
      socket.off("close", onClose)
      options.signal?.removeEventListener("abort", onAbort)
    }

    function onOpen() {
      cleanup()
      resolve(socket)
    }

    function onError(error: unknown) {
      socket.on("error", () => {})
      cleanup()
      reject(error instanceof Error ? error : new Error(errorMessage(error), { cause: error }))
    }

    function onClose(code: number, reason: Buffer) {
      cleanup()
      reject(new Error(closeMessage("WebSocket closed before open", code, reason)))
    }

    function onAbort() {
      cleanup()
      socket.on("error", () => {})
      socket.terminate()
      reject(abortError(options.signal))
    }

    socket.once("open", onOpen)
    socket.once("error", onError)
    socket.once("close", onClose)
    options.signal?.addEventListener("abort", onAbort, { once: true })
  })
}

export function streamResponsesWebSocket(options: StreamResponsesWebSocketOptions) {
  const encoder = new TextEncoder()

  let socket = options.socket
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined
  let cleanupSocket = () => {}
  let completed = false
  let emitted = false
  let idleTimer: ReturnType<typeof setTimeout> | undefined

  function cleanup() {
    if (idleTimer) clearTimeout(idleTimer)
    cleanupSocket()
    options.signal?.removeEventListener("abort", onAbort)
  }

  function terminateSocket(target = socket) {
    target.on("error", () => {})
    target.terminate()
  }

  function closeCompleted() {
    cleanup()
    controller?.enqueue(encoder.encode("data: [DONE]\n\n"))
    controller?.close()
  }

  function invalidate(error: ProviderError.ResponseStreamError, closeCode?: number) {
    if (completed) return
    completed = true
    cleanup()
    options.onConnectionInvalid?.(error, closeCode)
    controller?.error(error)
  }

  function resetIdleTimeout(message: string) {
    if (completed) return
    if (!options.idleTimeout) return
    if (idleTimer) clearTimeout(idleTimer)
    idleTimer = setTimeout(() => invalidate(new ProviderError.ResponseStreamError(message)), options.idleTimeout)
  }

  async function onMessage(data: WebSocket.RawData, isBinary: boolean) {
    if (completed) return
    if (isBinary) {
      invalidate(new ProviderError.ResponseStreamError("Unexpected binary WebSocket frame"))
      return
    }

    const text = data.toString()
    const event = (() => {
      try {
        const parsed = JSON.parse(text)
        return typeof parsed === "object" && parsed !== null ? parsed : undefined
      } catch {
        return undefined
      }
    })()

    if (event?.type === "error" && options.onRetryableTerminal) {
      cleanupSocket()
      if (idleTimer) clearTimeout(idleTimer)
      idleTimer = undefined
      try {
        const next = await options.onRetryableTerminal(event)
        if (completed) {
          if (next) terminateSocket(next)
          return
        }
        if (next) {
          attach(next)
          return
        }
      } catch (error) {
        invalidate(
          new ProviderError.ResponseStreamError(error instanceof Error ? error.message : String(error), {
            cause: error,
          }),
        )
        return
      }
    }

    const wrappedError = parseWrappedError(event, text)
    if (wrappedError && event) {
      if (!emitted) options.onFirstEvent?.(wrappedError)
      completed = true
      cleanup()
      options.onTerminal?.(event)
      controller?.error(
        new APICallError({
          message: wrappedError.message,
          url: socket.url,
          requestBodyValues: options.body,
          statusCode: wrappedError.status,
          responseHeaders: wrappedError.headers,
          responseBody: wrappedError.body,
        }),
      )
      return
    }

    if (!emitted) options.onFirstEvent?.()
    controller?.enqueue(
      encoder.encode(
        `${text
          .split(/\r?\n/)
          .map((line) => `data: ${line}`)
          .join("\n")}\n\n`,
      ),
    )
    emitted = true
    resetIdleTimeout("idle timeout waiting for websocket")

    if (!event) return

    if (event.type === "response.completed" || event.type === "response.done") {
      completed = true
      options.onComplete?.(event)
      options.onTerminal?.(event)
      closeCompleted()
      return
    }

    if (event.type === "response.failed" || event.type === "response.incomplete" || event.type === "error") {
      completed = true
      options.onTerminal?.(event)
      closeCompleted()
    }
  }

  function onError(error: Error) {
    invalidate(new ProviderError.ResponseStreamError(error.message, { cause: error }))
  }

  function onClose(code: number, reason: Buffer) {
    if (completed) return
    invalidate(
      new ProviderError.ResponseStreamError(closeMessage("WebSocket closed before response.completed", code, reason)),
      code,
    )
  }

  function onAbort() {
    const error = abortError(options.signal)
    if (completed) return
    completed = true
    cleanup()
    terminateSocket()
    options.onAbort?.(error)
    controller?.error(error)
  }

  function onCancel(reason: unknown) {
    if (completed) return
    completed = true
    cleanup()
    terminateSocket()
    options.onAbort?.(cancelError(reason))
  }

  function attach(next: WebSocket) {
    cleanupSocket()
    socket = next
    socket.on("message", onMessage)
    socket.once("error", onError)
    socket.once("close", onClose)
    cleanupSocket = () => {
      socket.off("message", onMessage)
      socket.off("error", onError)
      socket.off("close", onClose)
    }
    const { stream: _stream, background: _background, ...payload } = options.body
    resetIdleTimeout("idle timeout sending websocket request")
    socket.send(JSON.stringify({ type: "response.create", ...payload }), (error) => {
      if (completed) return
      resetIdleTimeout("idle timeout waiting for websocket")
      if (error) invalidate(new ProviderError.ResponseStreamError(error.message, { cause: error }))
    })
  }

  return new Response(
    new ReadableStream<Uint8Array>({
      start(next) {
        controller = next
        options.signal?.addEventListener("abort", onAbort, { once: true })

        if (options.signal?.aborted) {
          onAbort()
          return
        }

        attach(socket)
      },
      cancel(reason) {
        onCancel(reason)
      },
    }),
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  )
}

function parseWrappedError(event: Record<string, unknown> | undefined, body: string) {
  if (event?.type !== "error") return
  const status = event.status ?? event.status_code
  if (typeof status !== "number" || (status >= 200 && status < 300)) return
  return {
    status,
    headers: isRecord(event.headers)
      ? Object.fromEntries(
          Object.entries(event.headers).flatMap(([key, value]) =>
            typeof value === "string" || typeof value === "number" || typeof value === "boolean"
              ? [[key, String(value)]]
              : [],
          ),
        )
      : undefined,
    body,
    message: isRecord(event.error) && typeof event.error.message === "string" ? event.error.message : `${status}`,
  }
}

function cancelError(reason: unknown) {
  if (isAbortError(reason)) return reason
  if (reason instanceof Error) return reason
  return new DOMException(typeof reason === "string" ? reason : "Aborted", "AbortError")
}

function abortError(signal: AbortSignal | undefined) {
  const reason = signal?.reason
  if (isAbortError(reason)) return reason
  return new DOMException(reason instanceof Error ? reason.message : "Aborted", "AbortError")
}

function closeMessage(message: string, code: number, reason: Buffer) {
  const details = [`code ${code}`]
  if (code === MESSAGE_TOO_BIG_CLOSE_CODE) details.push("message too big")
  if (reason.length > 0) details.push(reason.toString())
  return `${message} (${details.join(": ")})`
}

export * as OpenAIWebSocket from "./ws"
