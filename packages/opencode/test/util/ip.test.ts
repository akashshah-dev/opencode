import { test, expect } from "bun:test"
import { IP } from "@/util/ip"

test("accepts valid IPv4 literals", () => {
  expect(IP.isIPLiteral("127.0.0.1")).toBe(true)
  expect(IP.isIPLiteral("192.168.1.20")).toBe(true)
  expect(IP.isIPLiteral("255.255.255.255")).toBe(true)
  expect(IP.isIPLiteral("[127.0.0.1]")).toBe(true)
})

test("rejects invalid IPv4 numerics", () => {
  expect(IP.isIPLiteral("999.999.999.999")).toBe(false)
  expect(IP.isIPLiteral("1.2.3.256")).toBe(false)
  expect(IP.isIPLiteral("1.2.3")).toBe(false)
  expect(IP.isIPLiteral("1.2.3.4.5")).toBe(false)
})

test("accepts valid IPv6 literals", () => {
  expect(IP.isIPLiteral("::1")).toBe(true)
  expect(IP.isIPLiteral("::")).toBe(true)
  expect(IP.isIPLiteral("fe80::1")).toBe(true)
  expect(IP.isIPLiteral("1:2:3:4:5:6:7:8")).toBe(true)
  expect(IP.isIPLiteral("::ffff:1.2.3.4")).toBe(true)
  expect(IP.isIPLiteral("[::1]")).toBe(true)
})

test("rejects invalid IPv6 literals", () => {
  // "::" must compress at least one group.
  expect(IP.isIPLiteral("1:2:3:4:5:6:7:8::")).toBe(false)
  expect(IP.isIPLiteral("1::2::3")).toBe(false)
  // Embedded IPv4 only as the final part.
  expect(IP.isIPLiteral("1.2.3.4::")).toBe(false)
  expect(IP.isIPLiteral("1.2.3.4::5")).toBe(false)
  expect(IP.isIPLiteral("1::2.3.4.999")).toBe(false)
  expect(IP.isIPLiteral("fe80::1%eth0")).toBe(false)
})

test("rejects non-literals", () => {
  expect(IP.isIPLiteral("example.com")).toBe(false)
  expect(IP.isIPLiteral("localhost")).toBe(false)
  expect(IP.isIPLiteral("proxy.corp")).toBe(false)
  expect(IP.isIPLiteral("")).toBe(false)
})
