export * as ConfigProxyV1 from "./proxy"

import { Schema } from "effect"

export const Type = Schema.Literals(["http", "https", "socks4", "socks5", "socks5h"]).annotate({
  description: "Proxy protocol. Use socks5h for remote DNS resolution through the proxy.",
})
export type Type = Schema.Schema.Type<typeof Type>

export const Entry = Schema.Struct({
  name: Schema.String.annotate({
    description: "Display name shown in the proxy picker",
  }),
  enabled: Schema.optional(Schema.Boolean).annotate({
    description: "Disabled proxies are hidden from selection but retained. Defaults to true.",
  }),
  type: Type,
  url: Schema.String.annotate({
    description:
      "Proxy address as host:port or full URL. Must not embed credentials, use username/passwordEnv instead.",
  }),
  username: Schema.optional(Schema.String).annotate({
    description: "Username for proxy authentication. Stored in plaintext by design.",
  }),
  passwordEnv: Schema.optional(Schema.String).annotate({
    description:
      "Name of an environment variable holding the proxy password. The password itself is never stored in config.",
  }),
  noProxy: Schema.optional(Schema.mutable(Schema.Array(Schema.String))).annotate({
    description: "Hosts that bypass this proxy, same syntax as NO_PROXY. Loopback hosts always bypass.",
  }),
}).annotate({ identifier: "ProxyConfig" })
export type Entry = Schema.Schema.Type<typeof Entry>

export const Info = Schema.Struct({
  default: Schema.optional(Schema.String).annotate({
    description: 'Default proxy id for sessions without an explicit choice, or "direct" / "env".',
  }),
  proxies: Schema.optional(Schema.Record(Schema.String, Entry)).annotate({
    description: "Configured proxies keyed by id",
  }),
}).annotate({ identifier: "ProxiesConfig" })
export type Info = Schema.Schema.Type<typeof Info>
