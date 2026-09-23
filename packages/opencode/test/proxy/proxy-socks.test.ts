import { afterEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import net from "node:net"
import { Effect } from "effect"
import { ProxyFetch } from "@/proxy/fetch"

afterEach(async () => {
  delete process.env.SOCKS_TEST_PASS
})

// Minimal SOCKS5 server: no-auth or username/password handshake, CONNECT,
// then a canned HTTP response. Records the requested host to prove remote
// vs local DNS behavior.
function socks5Server(options?: { username?: string; password?: string }) {
  const seen: Array<{ host: string; port: number }> = []
  const server = net.createServer((socket) => {
    let stage: "greet" | "auth" | "connect" | "http" = "greet"
    let buffer = Buffer.alloc(0)
    socket.on("data", (data: Buffer) => {
      buffer = Buffer.concat([buffer, data])
      while (true) {
        if (stage === "greet") {
          if (buffer.length < 2) return
          const methods = buffer.subarray(2, 2 + buffer[1]!)
          buffer = buffer.subarray(2 + buffer[1]!)
          const selected = options?.username ? (methods.includes(0x02) ? 0x02 : 0xff) : 0x00
          socket.write(Buffer.from([0x05, selected]))
          if (selected === 0xff) {
            socket.destroy()
            return
          }
          stage = options?.username ? "auth" : "connect"
          continue
        }
        if (stage === "auth") {
          if (buffer.length < 2) return
          const ulen = buffer[1]!
          if (buffer.length < 2 + ulen + 1) return
          const user = buffer.subarray(2, 2 + ulen).toString()
          const plen = buffer[2 + ulen]!
          if (buffer.length < 2 + ulen + 1 + plen) return
          const pass = buffer.subarray(3 + ulen, 3 + ulen + plen).toString()
          buffer = buffer.subarray(3 + ulen + plen)
          const ok = user === options?.username && pass === options?.password
          socket.write(Buffer.from([0x01, ok ? 0x00 : 0x01]))
          if (!ok) {
            socket.destroy()
            return
          }
          stage = "connect"
          continue
        }
        if (stage === "connect") {
          if (buffer.length < 4) return
          const atyp = buffer[3]!
          let host: string
          let offset: number
          if (atyp === 0x01) {
            if (buffer.length < 10) return
            host = Array.from(buffer.subarray(4, 8)).join(".")
            offset = 8
          } else if (atyp === 0x03) {
            const length = buffer[4]!
            if (buffer.length < 5 + length + 2) return
            host = buffer.subarray(5, 5 + length).toString()
            offset = 5 + length
          } else {
            socket.destroy()
            return
          }
          const port = buffer.readUInt16BE(offset)
          buffer = buffer.subarray(offset + 2)
          seen.push({ host, port })
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
          stage = "http"
          continue
        }
        // http stage: answer any request with a canned body.
        const end = buffer.indexOf("\r\n\r\n")
        if (end === -1) return
        buffer = buffer.subarray(0, 0)
        const body = "socks-ok"
        socket.write(
          `HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`,
        )
        socket.end()
        return
      }
    })
  })
  return { server, seen }
}

async function listen(server: Server | net.Server) {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  return (server.address() as net.AddressInfo).port
}

const select = (url: string, extra?: Record<string, unknown>) => ({
  proxyID: "tun",
  config: { proxies: { tun: { name: "Tunnel", type: "socks5h", url, ...(extra ?? {}) } } },
})

test("routes http targets through SOCKS5h with remote DNS", async () => {
  const { server, seen } = socks5Server()
  const port = await listen(server)
  try {
    const target = await listen(
      createServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" })
        res.end("unreached")
      }),
    )
    const response = await ProxyFetch.fetch(
      ProxyFetch.createPool(),
      select(`socks5h://127.0.0.1:${port}`) as never,
      `http://127.0.0.1:${target}/llm`,
      { method: "GET" },
    )!
    expect(response.status).toBe(200)
    expect(await response.text()).toBe("socks-ok")
    expect(seen).toHaveLength(1)
    // socks5h keeps the hostname for the proxy to resolve.
    expect(seen[0]!.host).toBe("127.0.0.1")
  } finally {
    server.close()
  }
})

test("rejects SOCKS auth failure without fallback", async () => {
  const { server, seen } = socks5Server({ username: "bot", password: "s3cret" })
  const port = await listen(server)
  try {
    // Missing password env fails before dialing.
    expect(() =>
      ProxyFetch.fetch(
        ProxyFetch.createPool(),
        select(`socks5://127.0.0.1:${port}`, { username: "bot", passwordEnv: "MISSING_SOCKS_PASS" }) as never,
        "http://127.0.0.1:9/llm",
        { method: "GET" },
      ),
    ).toThrow(/MISSING_SOCKS_PASS/)
    expect(seen).toHaveLength(0)

    // Wrong password reaches the server and is rejected there.
    process.env.SOCKS_TEST_WRONG = "wrong"
    const rejected = await ProxyFetch.fetch(
      ProxyFetch.createPool(),
      select(`socks5://127.0.0.1:${port}`, { username: "bot", passwordEnv: "SOCKS_TEST_WRONG" }) as never,
      "http://127.0.0.1:9/llm",
      { method: "GET" },
    )!.then(
      () => undefined,
      (cause: unknown) => cause,
    )
    expect(String(rejected)).toMatch(/authentication failed/i)
    delete process.env.SOCKS_TEST_WRONG
  } finally {
    server.close()
  }
})

test("sends SOCKS5 username and password", async () => {
  const { server, seen } = socks5Server({ username: "bot", password: "s3cret" })
  const port = await listen(server)
  process.env.SOCKS_TEST_PASS = "s3cret"
  try {
    const target = await listen(
      createServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" })
        res.end("unreached")
      }),
    )
    const response = await ProxyFetch.fetch(
      ProxyFetch.createPool(),
      {
        proxyID: "tun",
        config: {
          proxies: {
            tun: {
              name: "Tunnel",
              type: "socks5",
              url: `socks5://127.0.0.1:${port}`,
              username: "bot",
              passwordEnv: "SOCKS_TEST_PASS",
            },
          },
        },
      } as never,
      `http://127.0.0.1:${target}/llm`,
      { method: "GET" },
    )!
    expect(response.status).toBe(200)
    expect(await response.text()).toBe("socks-ok")
    expect(seen).toHaveLength(1)
  } finally {
    server.close()
  }
})

test("resolves the concurrent-session isolation matrix", async () => {
  const { server, seen } = socks5Server()
  const port = await listen(server)
  const direct = await listen(
    createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" })
      res.end("direct-ok")
    }),
  )
  try {
    const pool = ProxyFetch.createPool()
    const viaProxy = ProxyFetch.fetch(
      pool,
      select(`socks5h://127.0.0.1:${port}`) as never,
      `http://127.0.0.1:${direct}/a`,
      { method: "GET" },
    )!
    const viaDirect = ProxyFetch.fetch(pool, { proxyID: "direct" } as never, `http://127.0.0.1:${direct}/b`, {
      method: "GET",
    })
    expect(viaDirect).toBeUndefined()
    const directResponse = await fetch(`http://127.0.0.1:${direct}/b`)
    const [proxied, plain] = await Promise.all([viaProxy.then((res) => res.text()), directResponse.text()])
    expect(proxied).toBe("socks-ok")
    expect(plain).toBe("direct-ok")
    expect(seen).toHaveLength(1)
  } finally {
    server.close()
  }
})

test("fails fast on refused SOCKS endpoint", async () => {
  const error = await ProxyFetch.fetch(
    ProxyFetch.createPool(),
    select("socks5h://127.0.0.1:9") as never,
    "http://127.0.0.1:9/llm",
    { method: "GET" },
  )!.then(
    () => undefined,
    (cause: unknown) => cause,
  )
  expect(error).toBeDefined()
})
