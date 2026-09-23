export * as ConfigProxy from "./proxy"

import { Schema } from "effect"

export class Entry extends Schema.Class<Entry>("ConfigV2.Proxy.Entry")({
  name: Schema.String,
  enabled: Schema.Boolean.pipe(Schema.optional),
  type: Schema.Literals(["http", "https", "socks4", "socks5", "socks5h"]),
  url: Schema.String,
  username: Schema.String.pipe(Schema.optional),
  passwordEnv: Schema.String.pipe(Schema.optional),
  noProxy: Schema.String.pipe(Schema.Array, Schema.optional),
}) {}

export class Info extends Schema.Class<Info>("ConfigV2.Proxy")({
  default: Schema.String.pipe(Schema.optional),
  proxies: Schema.Record(Schema.String, Entry).pipe(Schema.optional),
}) {}
