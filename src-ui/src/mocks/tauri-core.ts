/**
 * Browser-only UI fixtures. Vite aliases Tauri IPC here only in preview mode.
 * All paths, events and service states below are fictional display data.
 * This module never accesses a backend, filesystem, network or native Tauri API.
 */
import type { AgentInfo, AppStatus, GuardInfo, SecurityEvent } from "../lib/api";

const previewRoot = "/ui-preview";
const configPath = `${previewRoot}/.qise/shield.yaml`;
const snapshotTime = Date.now();
const minutesAgo = (minutes: number) => new Date(snapshotTime - minutes * 60_000).toISOString();

// Names, strategies and pipeline assignments mirror the current guard registry.
// The five rules-based enforcing guards match ShieldConfig's balanced defaults.
const guards: GuardInfo[] = [
  { name: "prompt", mode: "observe", pipeline: "ingress", primary_strategy: "ai" },
  { name: "tool_sanity", mode: "observe", pipeline: "ingress", primary_strategy: "ai" },
  { name: "context", mode: "observe", pipeline: "ingress", primary_strategy: "ai" },
  { name: "supply_chain", mode: "observe", pipeline: "ingress", primary_strategy: "ai" },
  { name: "reasoning", mode: "observe", pipeline: "egress/output", primary_strategy: "ai" },
  { name: "command", mode: "enforce", pipeline: "egress", primary_strategy: "rules" },
  { name: "filesystem", mode: "enforce", pipeline: "egress", primary_strategy: "rules" },
  { name: "network", mode: "enforce", pipeline: "egress", primary_strategy: "rules" },
  { name: "exfil", mode: "observe", pipeline: "egress", primary_strategy: "ai" },
  { name: "resource", mode: "observe", pipeline: "egress", primary_strategy: "rules" },
  { name: "tool_policy", mode: "enforce", pipeline: "egress", primary_strategy: "rules" },
  { name: "credential", mode: "enforce", pipeline: "output", primary_strategy: "rules" },
  { name: "audit", mode: "observe", pipeline: "output", primary_strategy: "rules" },
  { name: "output", mode: "observe", pipeline: "output", primary_strategy: "ai" },
];

const agents: AgentInfo[] = [
  {
    key: "codex", name: "Codex", installed: true, protected: true, configured: true,
    can_protect: true, protection_status: "protected", experimental: false,
    coverage: ["preflight", "model_traffic"], cli_path: `${previewRoot}/bin/codex`,
    config_path: `${previewRoot}/.codex/config.toml`,
    note: "示例：模型流量已接入代理，配置备份就绪。",
  },
  {
    key: "claude-code", name: "Claude Code", installed: true, protected: true, configured: true,
    can_protect: true, protection_status: "protected", experimental: false,
    coverage: ["preflight", "model_traffic"], cli_path: `${previewRoot}/bin/claude`,
    config_path: `${previewRoot}/.claude/settings.json`,
    note: "示例：已验证模型流量连接。",
  },
  {
    key: "openclaw", name: "OpenClaw", installed: true, protected: false, configured: true,
    can_protect: true, protection_status: "needs_attention", experimental: true,
    coverage: ["preflight", "model_traffic"], cli_path: `${previewRoot}/bin/openclaw`,
    config_path: `${previewRoot}/.openclaw/openclaw.json`,
    note: "示例：已有配置备份，上游地址发生变化，需要重新检查连接。",
  },
  {
    key: "opencode", name: "OpenCode", installed: false, protected: false, configured: false,
    can_protect: true, protection_status: "not_protected", experimental: true,
    coverage: ["preflight", "model_traffic"], cli_path: "", config_path: "",
    note: "示例：未检测到安装。",
  },
  {
    key: "workbuddy", name: "WorkBuddy", installed: true, protected: false, configured: false,
    can_protect: false, protection_status: "not_protected", experimental: true,
    coverage: ["preflight", "manual_connection"], cli_path: `${previewRoot}/bin/workbuddy`,
    config_path: `${previewRoot}/.workbuddy/config.json`,
    note: "示例：支持安全体检，模型连接需要手动配置。",
  },
];

interface EventExample {
  minutes: number;
  guard: string;
  verdict: "block" | "warn" | "info" | "pass";
  message: string;
  resource: string;
  agent?: string;
  stage?: string;
  source?: string;
}

function makeEvent(example: EventExample, index: number): SecurityEvent {
  const { guard, verdict } = example;
  return {
    id: `evt_ui_preview_${index + 1}`,
    schema_version: "0.1",
    timestamp: minutesAgo(example.minutes),
    stage: example.stage ?? "runtime",
    source: example.source ?? "proxy",
    agent: { name: example.agent ?? "Codex", type: "coding_agent", session_id: "preview-session" },
    action: { type: "tool_call", name: guard, resource: example.resource },
    risk: {
      category: verdict === "info" ? "Protection Notice" : guard,
      severity: verdict === "block" ? "high" : verdict === "warn" ? "medium" : "info",
      confidence: verdict === "block" ? 0.99 : verdict === "warn" ? 0.82 : 1,
    },
    decision: {
      verdict,
      mode: guards.find((entry) => entry.name === guard)?.mode ?? "observe",
      blocked_by: verdict === "block" ? [guard] : [],
    },
    evidence: [{
      type: "guard_result", guard, verdict, rule_id: `preview.${guard}.${index + 1}`,
      message: example.message, path: example.resource,
      evidence_kind: verdict === "info" ? "precaution" : "finding",
    }],
    recommendation: verdict === "block" ? "示例建议：确认操作范围与授权后再继续。" : "仅为 UI 展示的示例记录。",
    correlation_id: `preview-correlation-${index + 1}`,
    raw_ref: "",
  };
}

const events: SecurityEvent[] = ([
  { minutes: 2, guard: "command", verdict: "block", message: "检测到递归删除操作，已阻止执行。", resource: "rm -rf /ui-preview/workspace" },
  { minutes: 6, guard: "prompt", verdict: "warn", message: "工具返回内容包含可疑指令，建议检查上下文。", resource: "docs/deployment.md", agent: "Claude Code" },
  { minutes: 12, guard: "credential", verdict: "block", message: "输出包含疑似访问凭据，已拦截敏感内容。", resource: "model response", agent: "Claude Code" },
  { minutes: 18, guard: "audit", verdict: "info", message: "运行观察已记录会话开始与工作目录。", resource: "/ui-preview/workspace", source: "observer" },
  { minutes: 26, guard: "filesystem", verdict: "pass", message: "读取项目源文件，路径检查通过。", resource: "/ui-preview/workspace/src/App.tsx", source: "observer" },
  { minutes: 34, guard: "supply_chain", verdict: "warn", message: "技能声明了额外网络权限，建议人工复核。", resource: "skills/demo-helper/SKILL.md", stage: "preflight", agent: "OpenClaw" },
  { minutes: 47, guard: "network", verdict: "block", message: "目标地址属于受限制的内部网络范围。", resource: "http://192.0.2.10/internal" },
  { minutes: 63, guard: "tool_policy", verdict: "pass", message: "工具调用符合当前允许策略。", resource: "read_file: README.md", agent: "Claude Code", source: "observer" },
] satisfies EventExample[]).map(makeEvent);

const slm = {
  configured: true,
  provider: "ollama",
  model: "qwen3:4b",
  base_url: "http://localhost:11434/v1",
  verification: "ready",
  server_running: true,
  timeout_ms: 5000,
  config_path: configPath,
};

const protectedAgents = Object.fromEntries(agents.filter((agent) => agent.configured).map((agent) => [agent.key, {
  agent: agent.key,
  display_name: agent.name,
  config_path: agent.config_path,
  backup_path: `${previewRoot}/.qise/backups/${agent.key}/original-config.bak`,
  proxy_url: "http://127.0.0.1:8822/v1",
  upstream_url: "https://api.example.com/v1",
  protected_at: minutesAgo(180),
}]));

const status: AppStatus = {
  config: configPath,
  state_path: `${previewRoot}/.qise/state.json`,
  events_path: `${previewRoot}/.qise/events.jsonl`,
  services: {
    proxy: { status: "running", port: 8822, managed_by: "qise", started_at: minutesAgo(180), upstream_url: "https://api.example.com/v1" },
    bridge: { status: "running", port: 8823, managed_by: "qise", started_at: minutesAgo(180) },
  },
  proxy: { host: "127.0.0.1", port: 8822, status: "listening", detail: "示例代理状态" },
  bridge: { host: "127.0.0.1", port: 8823, status: "listening", detail: "示例桥接状态" },
  slm,
  protected_agents: protectedAgents,
  detected_agents: agents,
  events_24h: { blocked: 3, warnings: 2 },
  last_event: events[0],
  services_running: true,
  protection_enabled: true,
};

const defaultConfig = {
  version: "1.0",
  integration: {
    mode: "proxy",
    proxy: {
      port: 8822, target_agents: ["codex", "openclaw"], auto_takeover: true,
      crash_recovery: true, upstream_url: "", upstream_api_key: "",
    },
  },
  models: {
    slm: { base_url: "http://localhost:11434/v1", model: "", timeout_ms: 5000, api_key: null },
    llm: { base_url: "", model: "", timeout_ms: 5000, api_key: null },
  },
  guards: { enabled: guards.map((guard) => guard.name), config: {} },
};

const config = {
  ...defaultConfig,
  models: {
    slm: { ...defaultConfig.models.slm, model: slm.model },
    llm: { ...defaultConfig.models.llm, base_url: "https://api.example.com/v1", model: "preview-review-model" },
  },
  integration: {
    ...defaultConfig.integration,
    proxy: { ...defaultConfig.integration.proxy, upstream_url: "https://api.example.com/v1" },
  },
  guards: {
    enabled: guards.map((guard) => guard.name),
    config: Object.fromEntries(guards.map((guard) => [guard.name, {
      mode: guard.mode,
      slm_confidence_threshold: guard.primary_strategy === "ai" ? 0.7 : null,
      skip_slm_on_rule_pass: guard.primary_strategy === "rules",
      slm_override_rule_warn_threshold: null,
    }])),
  },
};

const doctor = {
  result: "ready_with_warnings",
  checks: [
    { name: "Qise", status: "ok", detail: "0.2.1 (UI preview)" },
    { name: "Python", status: "ok", detail: "3.12 (示例)" },
    { name: "Config", status: "ok", detail: configPath },
    { name: "Event log", status: "ok", detail: status.events_path },
    { name: "Upstream", status: "ok", detail: "https://api.example.com/v1" },
    { name: "Proxy port", status: "ok", detail: "127.0.0.1:8822 (示例)" },
    { name: "Bridge port", status: "ok", detail: "127.0.0.1:8823 (示例)" },
    { name: "SLM", status: "ready", detail: "qwen3:4b (示例)" },
  ],
  warnings: ["示例：OpenClaw 连接需要检查；所有诊断结果均为 UI 预览数据。"],
  errors: [],
};

const disabledCommands = new Set([
  "save_config", "set_guard_mode", "toggle_protection", "takeover_agent",
  "protect_agent_with_options", "restore_agent", "restore_all_agents", "stop_qise_services",
  "slm_start", "slm_stop", "scan_skill", "scan_mcp", "scan_agent_config",
  "scan_agent_assets", "scan_all_agents", "run_check", "get_context",
]);

/** Return fresh fixture copies so UI edits cannot mutate later read results. */
export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  let result: unknown;
  switch (cmd) {
    case "get_status": result = status; break;
    case "get_events": {
      const limit = typeof args?.limit === "number" && Number.isFinite(args.limit)
        ? Math.max(0, Math.floor(args.limit)) : events.length;
      result = events.slice(0, limit);
      break;
    }
    case "get_guards": result = guards; break;
    case "detect_agents": result = agents; break;
    case "get_config": result = config; break;
    case "get_default_config": result = defaultConfig; break;
    case "get_config_path": result = configPath; break;
    case "get_slm_status": result = slm; break;
    case "get_doctor": result = doctor; break;
    case "get_takeover_status": result = protectedAgents; break;
    case "get_adapter_snippet":
      result = `# UI 预览示例 · ${String(args?.adapter ?? "nanobot")}\n# 仅展示集成片段排版，未连接或执行任何服务。\n\nQISE_PROXY_URL = "http://127.0.0.1:8822/v1"\nQISE_BRIDGE_URL = "http://127.0.0.1:8823"\n`;
      break;
    default:
      if (disabledCommands.has(cmd)) {
        throw new Error("UI 预览模式：此操作仅用于展示界面，未执行真实操作。配置、扫描、保护与模型服务均不会被修改或启动。");
      }
      throw new Error(`UI 预览模式：未提供命令 ${cmd} 的展示数据，未执行真实操作。`);
  }
  return structuredClone(result) as T;
}
