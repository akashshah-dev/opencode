import { createMemo, createSignal } from "solid-js"
import { useLocal } from "../context/local"
import { useSync } from "../context/sync"
import { useSDK } from "../context/sdk"
import { DialogSelect } from "../ui/dialog-select"
import { DialogPrompt } from "../ui/dialog-prompt"
import { DialogConfirm } from "../ui/dialog-confirm"
import { useDialog } from "../ui/dialog"
import { useToast } from "../ui/toast"
import { useTheme } from "../context/theme"
import { TextAttributes } from "@opentui/core"
import * as fuzzysort from "fuzzysort"
import type { ProxiesConfig, ProxyConfig } from "@opencode-ai/sdk/v2"

const DIRECT = "direct"
const SYSTEM = "env"
const RESERVED = new Set([DIRECT, SYSTEM])
const ID_PATTERN = /^[a-z0-9][a-z0-9-_]*$/

type ProxyValue = { kind: "direct" } | { kind: "env" } | { kind: "proxy"; id: string }

function parseValue(proxyID: string | undefined): ProxyValue {
  if (proxyID === DIRECT || !proxyID) return { kind: "direct" }
  if (proxyID === SYSTEM) return { kind: "env" }
  return { kind: "proxy", id: proxyID }
}

function displayTarget(entry: ProxyConfig) {
  const raw = entry.url.trim()
  const url = raw.includes("://") ? raw : `http://${raw}`
  if (!URL.canParse(url)) return entry.name
  const parsed = new URL(url)
  if (!parsed.hostname) return entry.name
  return `${entry.name}@${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`
}

function Status(props: { enabled: boolean }) {
  const { theme } = useTheme()
  if (props.enabled) {
    return <span style={{ fg: theme.success, attributes: TextAttributes.BOLD }}>✓ Enabled</span>
  }
  return <span style={{ fg: theme.textMuted }}>○ Disabled</span>
}

export function proxyLabel(config: ProxiesConfig | undefined, proxyID: string | undefined) {
  const value = parseValue(proxyID ?? config?.default)
  if (value.kind === "direct") return "Direct"
  if (value.kind === "env") return "System env"
  const entry = config?.proxies?.[value.id]
  // resolveForSession throws UnknownProxyError for missing ids instead of
  // going direct — label it distinctly so the footer never claims Direct
  // while requests fail fast.
  if (!entry) return "Unknown proxy"
  return displayTarget(entry)
}

export function DialogProxy(props: { sessionID: string }) {
  const local = useLocal()
  const sync = useSync()
  const sdk = useSDK()
  const dialog = useDialog()
  const toast = useToast()
  const [query, setQuery] = createSignal("")

  const config = createMemo(() => sync.data.config.proxy)
  const proxies = createMemo(() => config()?.proxies ?? {})
  // Match proxyLabel's effective resolution: an unset session choice falls
  // back to the config default, so the highlighted row agrees with the
  // footer instead of wrongly showing Direct.
  const current = createMemo<ProxyValue>(() => parseValue(local.proxy.current(props.sessionID) ?? config()?.default))

  async function select(value: ProxyValue) {
    const proxyID = value.kind === "direct" ? DIRECT : value.kind === "env" ? SYSTEM : value.id
    await local.proxy.set(props.sessionID, proxyID)
    dialog.clear()
  }

  async function toggle(id: string) {
    const entry = proxies()[id]
    if (!entry) return
    await saveConfig({
      ...config(),
      proxies: { ...proxies(), [id]: { ...entry, enabled: entry.enabled === false ? true : false } },
    })
    toast.show({ message: `Proxy ${entry.enabled === false ? "enabled" : "disabled"}: ${entry.name}`, variant: "info" })
  }

  async function saveConfig(proxy: ProxiesConfig | undefined) {
    const before = sync.data.config.proxy
    sync.set("config", "proxy", proxy)
    const result = await sdk.client.config.update({ config: { proxy } })
    if (result.error) {
      sync.set("config", "proxy", before)
      toast.show({ message: "Failed to save proxy configuration", variant: "error" })
      return false
    }
    await sdk.client.instance.dispose()
    await sync.bootstrap()
    return true
  }

  async function promptText(title: string, placeholder: string, value?: string) {
    return DialogPrompt.show(dialog, title, { placeholder, value })
  }

  async function promptEntry(existing?: { id: string; entry: ProxyConfig }) {
    const name = await promptText(existing ? "Proxy name" : "Add proxy", "Display name", existing?.entry.name)
    if (name === null) return
    if (!name.trim()) {
      toast.show({ message: "Proxy name is required", variant: "error" })
      return
    }
    const url = await promptText("Proxy address", "host:port or full URL (no credentials)", existing?.entry.url)
    if (url === null) return
    if (!url.trim()) {
      toast.show({ message: "Proxy address is required", variant: "error" })
      return
    }
    if (url.includes("@")) {
      toast.show({ message: "Proxy address must not embed credentials, use username/password instead", variant: "error" })
      return
    }
    const username = await promptText(
      "Username (optional)",
      "Leave empty for no auth",
      existing?.entry.username ?? "",
    )
    if (username === null) return
    let passwordEnv = existing?.entry.passwordEnv
    if (username.trim()) {
      const variable = await promptText(
        "Password env var (optional)",
        "Environment variable holding the password",
        existing?.entry.passwordEnv ?? "",
      )
      if (variable === null) return
      passwordEnv = variable.trim() ? variable.trim() : undefined
    } else {
      passwordEnv = undefined
    }

    let id = existing?.id
    if (!id) {
      const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "")
      if (!slug || !ID_PATTERN.test(slug) || RESERVED.has(slug)) {
        toast.show({
          message: `Could not derive a proxy id from "${name}". Use lowercase letters, numbers, hyphens.`,
          variant: "error",
        })
        return
      }
      if (proxies()[slug]) {
        toast.show({ message: `Proxy id "${slug}" already exists`, variant: "error" })
        return
      }
      id = slug
    }

    const entry: ProxyConfig = {
      name: name.trim(),
      type: existing?.entry.type ?? (url.trim().toLowerCase().startsWith("socks") ? "socks5h" : "http"),
      url: url.trim(),
      ...(username.trim() ? { username: username.trim() } : {}),
      ...(passwordEnv ? { passwordEnv } : {}),
      ...(existing?.entry.enabled === false ? { enabled: false } : {}),
    }
    const ok = await saveConfig({ ...config(), proxies: { ...proxies(), [id]: entry } })
    if (ok) toast.show({ message: existing ? `Proxy updated: ${entry.name}` : `Proxy added: ${entry.name}`, variant: "success" })
  }

  async function remove(id: string) {
    const entry = proxies()[id]
    if (!entry) return
    const ok = await DialogConfirm.show(dialog, "Remove proxy", `Remove proxy "${entry.name}"? Sessions using it revert to default.`)
    if (ok !== true) return
    const next = { ...proxies() }
    delete next[id]
    await saveConfig({ ...config(), proxies: next })
    toast.show({ message: `Proxy removed: ${entry.name}`, variant: "info" })
  }

  const options = createMemo(() => {
    const needle = query().trim()
    const showSections = needle.length === 0
    const currentValue = current()
    const currentKey =
      currentValue.kind === "direct" ? DIRECT : currentValue.kind === "env" ? SYSTEM : currentValue.id
    const recents = local.proxy.recent()
    const entries = Object.entries(proxies())

    const toOption = (value: ProxyValue, title: string, description: string | undefined, category: string | undefined) => ({
      value,
      title,
      description,
      category: showSections ? category : undefined,
      current: currentKey === (value.kind === "direct" ? DIRECT : value.kind === "env" ? SYSTEM : value.id),
      onSelect: () => select(value),
    })

    const directOption = toOption({ kind: "direct" }, "Direct", "Bypass all proxies", "Connection")
    const envOption = toOption({ kind: "env" }, "System environment", "Follow HTTP(S)_PROXY + NO_PROXY", "Connection")

    const entryOptions = entries.map(([id, entry]) => {
      const enabled = entry.enabled !== false
      return {
        value: { kind: "proxy", id } as ProxyValue,
        title: entry.name,
        description: displayTarget(entry),
        category: showSections ? (entry.type.startsWith("socks") ? "SOCKS" : "HTTP") : undefined,
        footer: <Status enabled={enabled} />,
        current: currentKey === id,
        onSelect: () => select({ kind: "proxy", id }),
      }
    })

    const recentOptions = recents.flatMap((id) => {
      const entry = proxies()[id]
      if (!entry) return []
      if (currentKey === id) return []
      return [
        {
          value: { kind: "proxy", id } as ProxyValue,
          title: entry.name,
          description: displayTarget(entry),
          category: showSections ? "Recent" : undefined,
          footer: <Status enabled={entry.enabled !== false} />,
          current: false,
          onSelect: () => select({ kind: "proxy", id }),
        },
      ]
    })

    const all = [directOption, envOption, ...recentOptions, ...entryOptions]
    if (!needle) return all
    return fuzzysort.go(needle, all, { keys: ["title", "description"] }).map((x) => x.obj)
  })

  return (
    <DialogSelect<ProxyValue>
      title="Proxy"
      options={options()}
      onFilter={setQuery}
      skipFilter={true}
      current={current()}
      actions={[
        {
          command: "dialog.proxy.toggle",
          title: "toggle",
          disabled: (option) => !option || option.value.kind !== "proxy",
          onTrigger: async (option) => {
            if (option.value.kind === "proxy") await toggle(option.value.id)
          },
        },
        {
          command: "dialog.proxy.add",
          title: "add",
          onTrigger: () => {
            void promptEntry()
          },
        },
        {
          command: "dialog.proxy.edit",
          title: "edit",
          disabled: (option) => !option || option.value.kind !== "proxy",
          onTrigger: async (option) => {
            if (option.value.kind !== "proxy") return
            const entry = proxies()[option.value.id]
            if (!entry) return
            await promptEntry({ id: option.value.id, entry })
          },
        },
        {
          command: "dialog.proxy.remove",
          title: "remove",
          disabled: (option) => !option || option.value.kind !== "proxy",
          onTrigger: async (option) => {
            if (option.value.kind === "proxy") await remove(option.value.id)
          },
        },
      ]}
    />
  )
}
