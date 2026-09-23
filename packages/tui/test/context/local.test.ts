import { expect, test } from "bun:test"
import { parseModel, recentModels } from "../../src/context/local"
import { proxyLabel } from "../../src/component/dialog-proxy"

test("parses model IDs containing slashes", () => {
  expect(parseModel("provider/family/model")).toEqual({
    providerID: "provider",
    modelID: "family/model",
  })
})

test("moves a model to the front, deduplicates, and limits recents", () => {
  const recent = Array.from({ length: 12 }, (_, index) => ({
    providerID: "provider",
    modelID: `model-${index}`,
  }))

  expect(recentModels({ providerID: "provider", modelID: "model-5" }, recent)).toEqual([
    { providerID: "provider", modelID: "model-5" },
    ...recent.slice(0, 5),
    ...recent.slice(6, 10),
  ])
})

test("proxy labels never expose passwords", () => {
  const config = {
    default: "corp",
    proxies: {
      corp: { name: "Corp", type: "http", url: "proxy.corp:8080", username: "bot", passwordEnv: "P" },
    },
  } as never
  expect(proxyLabel(config, undefined)).toBe("Corp@proxy.corp:8080")
  expect(proxyLabel(config, "direct")).toBe("Direct")
  expect(proxyLabel(config, "env")).toBe("System env")
  expect(proxyLabel(config, "corp")).toBe("Corp@proxy.corp:8080")
  expect(proxyLabel(config, "missing")).toBe("Unknown proxy")
  expect(proxyLabel(undefined, undefined)).toBe("Direct")
})
