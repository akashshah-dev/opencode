import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260923074549_session_proxy_id",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`session\` ADD \`proxy_id\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration
