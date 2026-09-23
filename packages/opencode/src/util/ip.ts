// Strict IP-literal detection for TLS SNI decisions. Only proven literals
// return true — invalid numerics ("999.999.999.999") and non-literals must
// keep `servername` instead of silently losing SNI. Mirrors the strictness of
// the SOCKS address parsers in @opencode-ai/llm (which additionally encode).

export function isIPv4Literal(host: string) {
  const parts = host.split(".")
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/.test(part))) return false
  return parts.every((part) => Number(part) <= 255)
}

export function isIPv6Literal(host: string) {
  if (!host.includes(":")) return false
  if (host.includes(".")) {
    // An embedded dotted-quad is only valid as the final part of the address.
    const match = /^(.*:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(host)
    if (!match || match[1]?.includes(".") || !isIPv4Literal(match[2]!)) return false
  }
  const halves = host.split("::")
  if (halves.length > 2) return false
  try {
    const head = countGroups(halves[0] ?? "", halves.length === 1)
    const tail = halves.length === 2 ? countGroups(halves[1] ?? "", true) : 0
    const missing = 8 - head - tail
    // "::" must compress at least one group: reject "1:2:3:4:5:6:7:8::".
    return halves.length === 1 ? missing === 0 : missing > 0
  } catch {
    return false
  }
}

function countGroups(group: string, isFinal: boolean) {
  if (group === "") return 0
  const parts = group.split(":")
  let count = 0
  parts.forEach((part, index) => {
    if (part.includes(".")) {
      // Dotted-quad only as the last part of the whole address, occupying two groups.
      if (!isFinal || index !== parts.length - 1 || !isIPv4Literal(part)) throw new Error("invalid")
      count += 2
      return
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) throw new Error("invalid")
    count += 1
  })
  return count
}

export function isIPLiteral(hostname: string) {
  const host = hostname.replace(/^\[|\]$/g, "")
  return isIPv4Literal(host) || isIPv6Literal(host)
}

export * as IP from "./ip"
