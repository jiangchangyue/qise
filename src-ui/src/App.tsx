import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import AgentPanel from "./components/AgentPanel";
import ConfigPanel from "./components/ConfigPanel";
import DiagnosticsPanel from "./components/DiagnosticsPanel";
import EventLog from "./components/EventLog";
import GuardList from "./components/GuardList";
import { useAppUpdater } from "./hooks/useAppUpdater";
import Icon from "./components/Icon";
import DesktopShell, { ToolsPage, type PageId } from "./components/DesktopShell";
import HomePage from "./components/HomeOverview";
import { BackupRestorePage, ObserverPage, IntegrationsPage, AdvancedLabPage } from "./components/UtilityPages";
export { default as HomePage } from "./components/HomeOverview";
import {
  AgentInfo,
  AppStatus,
  GuardInfo,
  SecurityEvent,
  normalizeAgentInfo,
  normalizeSecurityEvent,
  normalizeStatus,
  slmLabel,
  slmTone,
  statusHasConfiguredAgents,
  statusProtectionEnabled,
} from "./lib/api";
import {
  modeLabel,
  slmStatusLabel,
  statusWord,
  tr,
  verdictLabel,
  type Locale,
} from "./lib/locale";

type ScanMode = "all" | "agent" | "skill" | "mcp" | "agent-config";
type GuardPreset = "balanced" | "strict" | "observe";

interface CommandText {
  stdout: string;
  stderr: string;
  success: boolean;
  exit_status: string;
}

interface ScanFinding {
  verdict?: string;
  category?: string;
  severity?: string;
  confidence?: number;
  message?: string;
  path?: string;
  snippet?: string;
  rule_id?: string;
}

interface ScanReport {
  target?: string;
  target_type?: string;
  verdict?: string;
  risk?: {
    category?: string;
    severity?: string;
  };
  findings?: ScanFinding[];
  recommendation?: string;
}

interface ScanSkip {
  agent?: string;
  target_type?: string;
  reason?: string;
}

interface ScanCollection {
  target?: string;
  target_type?: string;
  verdict?: string;
  reports?: ScanReport[];
  skipped?: ScanSkip[];
  recommendation?: string;
  summary?: {
    reports?: number;
    block?: number;
    warn?: number;
    pass?: number;
    skipped?: number;
  };
}

type ScanResult = ScanReport | ScanCollection;

type TaskStatus = "idle" | "running" | "succeeded" | "failed";

interface TaskState<T> {
  status: TaskStatus;
  title: string;
  detail?: string;
  action?: string;
  startedAt?: string;
  finishedAt?: string;
  result?: T;
  error?: string;
}

interface PreflightRequest {
  mode: ScanMode;
  path: string;
  agent: string;
  selectedAgents: string[];
  includeSkills: boolean;
  includeMcp: boolean;
  includeAgentConfig: boolean;
}

interface SlmStartRequest {
  model: string;
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  noInstall: boolean;
  noPull: boolean;
  noVerify: boolean;
}

const GUARD_PRESETS: Record<GuardPreset, Partial<Record<string, string>>> = {
  balanced: {
    command: "enforce",
    credential: "enforce",
    filesystem: "enforce",
    network: "enforce",
    tool_policy: "enforce",
    prompt: "observe",
    reasoning: "observe",
    output: "observe",
    exfil: "observe",
    resource: "observe",
    audit: "observe",
    context: "observe",
    tool_sanity: "observe",
    supply_chain: "observe",
  },
  strict: {
    command: "enforce",
    credential: "enforce",
    filesystem: "enforce",
    network: "enforce",
    tool_policy: "enforce",
    prompt: "enforce",
    reasoning: "enforce",
    output: "enforce",
    exfil: "enforce",
    resource: "enforce",
    audit: "observe",
    context: "enforce",
    tool_sanity: "enforce",
    supply_chain: "enforce",
  },
  observe: {
    command: "observe",
    credential: "observe",
    filesystem: "observe",
    network: "observe",
    tool_policy: "observe",
    prompt: "observe",
    reasoning: "observe",
    output: "observe",
    exfil: "observe",
    resource: "observe",
    audit: "observe",
    context: "observe",
    tool_sanity: "observe",
    supply_chain: "observe",
  },
};

function badgeClass(verdict?: string): string {
  switch ((verdict || "pass").toLowerCase()) {
    case "block":
      return "badge-block";
    case "warn":
      return "badge-warn";
    case "info":
      return "badge-info";
    default:
      return "badge-pass";
  }
}

function resultText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

function commandText(result: CommandText): string {
  return result.stdout || result.stderr || `Qise command exited with ${result.exit_status}.`;
}

function requireCommandSuccess(result: CommandText): string {
  const output = commandText(result);
  if (!result.success) {
    throw new Error(output);
  }
  return output;
}

async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

function Spinner({ tone = "light" }: { tone?: "light" | "blue" }) {
  return (
    <span
      className={`qise-spinner ${tone === "blue" ? "qise-spinner-blue" : ""}`}
      aria-hidden="true"
    />
  );
}

function BusyButton({
  children,
  busy,
  busyLabel,
  locale = "en",
  variant = "primary",
  className = "",
  disabled,
  onClick,
}: {
  children: ReactNode;
  busy?: boolean;
  busyLabel?: string;
  locale?: Locale;
  variant?: "primary" | "secondary" | "danger";
  className?: string;
  disabled?: boolean;
  onClick?: () => void;
}) {
  const variantClass = {
    primary: "qise-action-primary",
    secondary: "qise-action-secondary",
    danger: "qise-action-danger",
  }[variant];

  return (
    <button
      className={`qise-action ${variantClass} ${className}`}
      disabled={disabled || busy}
      onClick={onClick}
    >
      {busy && <Spinner tone={variant === "primary" ? "light" : "blue"} />}
      <span>{busy ? busyLabel || tr(locale, "Working...", "处理中...") : children}</span>
    </button>
  );
}

function StatusPill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "green" | "yellow" | "red" | "blue" | "neutral";
}) {
  return <span className={`qise-pill qise-pill-${tone}`}>{children}</span>;
}

function createTask<T>(title = "No operation yet."): TaskState<T> {
  return { status: "idle", title };
}

function runningTask<T>(title: string, detail?: string, action?: string): TaskState<T> {
  return {
    status: "running",
    title,
    detail,
    action,
    startedAt: new Date().toISOString(),
  };
}

function succeededTask<T>(previous: TaskState<T>, result: T, detail?: string): TaskState<T> {
  return {
    ...previous,
    status: "succeeded",
    detail: detail ?? previous.detail,
    result,
    error: undefined,
    finishedAt: new Date().toISOString(),
  };
}

function failedTask<T>(previous: TaskState<T>, error: unknown): TaskState<T> {
  return {
    ...previous,
    status: "failed",
    error: String(error),
    finishedAt: new Date().toISOString(),
  };
}

function taskTone(task: TaskState<unknown>): "green" | "yellow" | "red" | "blue" {
  if (task.status === "running") return "blue";
  if (task.status === "succeeded") return "green";
  if (task.status === "failed") return "red";
  return "yellow";
}

function taskStatusText(task: TaskState<unknown>, locale: Locale): string {
  if (task.status === "running") return tr(locale, "Running", "运行中");
  if (task.status === "succeeded") return tr(locale, "Done", "完成");
  if (task.status === "failed") return tr(locale, "Failed", "失败");
  return tr(locale, "Idle", "空闲");
}

function TaskStrip({ tasks, locale }: { tasks: TaskState<unknown>[]; locale: Locale }) {
  const task = tasks.find(item => item.status === "running");
  if (!task) return null;
  return <div className="task-notice" role="status"><Spinner tone="blue" /><StatusPill tone={taskTone(task)}>{taskStatusText(task, locale)}</StatusPill><span>{task.title}</span></div>;
}

function isScanCollection(result: ScanResult | null): result is ScanCollection {
  return Boolean(result && Array.isArray((result as ScanCollection).reports));
}

function scanReports(result: ScanResult | null): ScanReport[] {
  if (!result) return [];
  return isScanCollection(result) ? result.reports ?? [] : [result as ScanReport];
}

function scanFindingCount(result: ScanResult | null): number {
  return scanReports(result).reduce((total, report) => total + (report.findings?.length ?? 0), 0);
}

function scanSummary(result: ScanResult | null) {
  const reports = scanReports(result);
  if (!result) {
    return { reports: 0, block: 0, warn: 0, pass: 0, skipped: 0 };
  }
  if (isScanCollection(result) && result.summary) {
    return {
      reports: result.summary.reports ?? reports.length,
      block: result.summary.block ?? 0,
      warn: result.summary.warn ?? 0,
      pass: result.summary.pass ?? 0,
      skipped: result.summary.skipped ?? result.skipped?.length ?? 0,
    };
  }
  return {
    reports: reports.length,
    block: reports.filter((report) => report.verdict === "block").length,
    warn: reports.filter((report) => report.verdict === "warn").length,
    pass: reports.filter((report) => report.verdict === "pass").length,
    skipped: 0,
  };
}

function BootScreen({ hint }: { hint: string; locale: Locale }) {
  return <div className="boot-screen"><span className="brand-mark"><Icon name="shield" size={28} /></span><h1>Qise</h1><p>{hint}</p><Spinner tone="blue" /></div>;
}

function ErrorBanner({ error, onDismiss, locale }: { error: string | null; onDismiss: () => void; locale: Locale }) {
  if (!error) return null;
  return (
    <div className="app-error" role="alert">
      <p className="">{error}</p>
      <button
        className="qise-action qise-action-secondary"
        onClick={onDismiss}
      >
        {tr(locale, "Dismiss", "关闭")}
      </button>
    </div>
  );
}

function AgentShieldPage({
  agents,
  task,
  onProtectAgent,
  onRestoreAgent,
  onRestoreAll,
  onStopServices,
  onProtectCustom,
  locale,
}: {
  agents: AgentInfo[];
  task: TaskState<string>;
  onProtectAgent: (agent: AgentInfo, baseUrl: string) => void;
  onRestoreAgent: (agent: AgentInfo) => void;
  onRestoreAll: () => void;
  onStopServices: () => void;
  onProtectCustom: (baseUrl: string) => void;
  locale: Locale;
}) {
  const [tab, setTab] = useState("agents");
  const [customBaseUrl, setCustomBaseUrl] = useState("");
  const busy = task.status === "running";
  const output = task.status === "failed" ? task.error : task.result;
  return <div className="page-stack">
    <div className="qise-tabs" role="tablist" aria-label={tr(locale, "Protection options", "保护选项")}>
      {[["agents", tr(locale, "Connected agents", "智能体列表")], ["custom", tr(locale, "Custom connection", "自定义接入")], ["recovery", tr(locale, "Recovery & services", "恢复与服务")]].map(([id, label]) => <button key={id} role="tab" aria-selected={tab === id} className={`qise-tab ${tab === id ? "is-active" : ""}`} onClick={() => setTab(id)}>{label}</button>)}
    </div>
    {tab === "agents" && <div className="fill-panel"><AgentPanel agents={agents} task={task} onProtect={onProtectAgent} onRestore={onRestoreAgent} locale={locale} /></div>}
    {tab === "custom" && <section className="workspace-panel connection-panel"><div className="workspace-panel-header"><Icon name="code" size={20} /><h2>{tr(locale, "Connect a custom agent", "接入自定义智能体")}</h2></div><div className="workspace-panel-body"><p className="muted-copy">{tr(locale, "Provide the upstream address for an OpenAI-compatible or Anthropic agent. Configure the client to use Qise after setup.", "填写 OpenAI 兼容接口或 Anthropic 上游地址，完成后在客户端中配置 Qise 代理。")}</p><label className="field-label">{tr(locale, "Upstream API URL", "上游接口地址")}<input className="qise-input" value={customBaseUrl} onChange={e => setCustomBaseUrl(e.target.value)} placeholder="https://api.example.com/v1" /></label><div className="inline-note"><Icon name="lock" size={16} />{tr(locale, "Your original model provider stays the same.", "继续使用你原来的模型服务商。")}</div></div><div className="workspace-panel-footer"><BusyButton busy={busy} disabled={!customBaseUrl.trim()} onClick={() => onProtectCustom(customBaseUrl)} locale={locale}>{tr(locale, "Set up connection", "创建保护连接")}</BusyButton></div></section>}
    {tab === "recovery" && <div className="recovery-grid"><section className="workspace-panel"><div className="workspace-panel-header"><Icon name="backup" /><h2>{tr(locale, "Restore original settings", "恢复原始配置")}</h2></div><div className="workspace-panel-body"><p className="muted-copy">{tr(locale, "Restore all agent settings previously changed by Qise. Your security records are retained.", "恢复曾被 Qise 修改的智能体配置，保留已有安全记录。")}</p></div><div className="workspace-panel-footer"><BusyButton variant="secondary" busy={busy && task.action === "restore-all"} disabled={busy} onClick={onRestoreAll} locale={locale}>{tr(locale, "Restore all agents", "恢复全部智能体")}</BusyButton></div></section><section className="workspace-panel"><div className="workspace-panel-header"><Icon name="activity" /><h2>{tr(locale, "Managed services", "本地保护服务")}</h2></div><div className="workspace-panel-body"><p className="muted-copy">{tr(locale, "Restore connections and stop the proxy and bridge managed by Qise.", "恢复接入配置，并停止 Qise 管理的代理与桥接服务。")}</p></div><div className="workspace-panel-footer"><BusyButton variant="danger" busy={busy && task.action === "stop"} disabled={busy} onClick={onStopServices} locale={locale}>{tr(locale, "Stop services", "停止保护服务")}</BusyButton></div></section></div>}
    {tab !== "agents" && output && <pre className="compact-output" role="status">{output}</pre>}
  </div>;
}

function PreflightPage({
  agents,
  setError,
  task,
  onRunScan,
  locale,
}: {
  agents: AgentInfo[];
  setError: (error: string | null) => void;
  task: TaskState<ScanResult>;
  onRunScan: (request: PreflightRequest) => void;
  locale: Locale;
}) {
  const [resultPage, setResultPage] = useState(0);
  const [resultTab, setResultTab] = useState("reports");
  const [mode, setMode] = useState<ScanMode>("all");
  const [path, setPath] = useState("");
  const [agent, setAgent] = useState(agents[0]?.key ?? "codex");
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [includeSkills, setIncludeSkills] = useState(true);
  const [includeMcp, setIncludeMcp] = useState(true);
  const [includeAgentConfig, setIncludeAgentConfig] = useState(true);

  useEffect(() => {
    if (!agent && agents[0]?.key) setAgent(agents[0].key);
  }, [agent, agents]);

  useEffect(() => {
    setSelectedAgents((current) => {
      if (current.length > 0) {
        return current.filter((key) => agents.some((item) => item.key === key));
      }
      return agents.filter((item) => item.installed).map((item) => item.key);
    });
  }, [agents]);

  function runScan() {
    setError(null);
    onRunScan({
      mode,
      path,
      agent,
      selectedAgents,
      includeSkills,
      includeMcp,
      includeAgentConfig,
    });
  }

  const busy = task.status === "running";
  const report = task.result ?? null;
  const needsPath = mode === "skill" || mode === "mcp";
  const needsAgent = mode === "agent" || mode === "agent-config";
  const hasCategory = includeSkills || includeMcp || includeAgentConfig;
  const canRun = busy
    || (needsPath && !path.trim())
    || (needsAgent && !agent.trim())
    || ((mode === "all" || mode === "agent") && !hasCategory);
  const summary = scanSummary(report);
  const reports = scanReports(report);

  const reportIndex = Math.min(resultPage, Math.max(0, reports.length - 1));
  const selectedReport = reports[reportIndex];
  return <div className="workspace-split scan-workspace">
    <section className="workspace-panel"><div className="workspace-panel-header"><Icon name="scan" /><h2>{tr(locale, "Check scope", "检查范围")}</h2><span className="subtle-label">{tr(locale, "01 / CONFIGURE", "01 / 配置")}</span></div>
      <div className="workspace-panel-body scan-config">
        <label className="field-label">{tr(locale, "What would you like to check?", "选择检查对象")}<select className="qise-input" value={mode} onChange={e => setMode(e.target.value as ScanMode)}>{([["all", "All agents", "全部智能体"], ["agent", "One agent", "单个智能体"], ["agent-config", "Agent config", "智能体配置"], ["skill", "Skill path", "技能路径"], ["mcp", "MCP config", "MCP 配置"]] as const).map(([id,en,zh]) => <option key={id} value={id}>{tr(locale,en,zh)}</option>)}</select></label>
        {mode === "all" && <fieldset><legend>{tr(locale, "Included agents", "参与检查的智能体")}</legend><div className="scan-agent-options">{agents.map(item => <label className="qise-check" key={item.key}><input type="checkbox" checked={selectedAgents.includes(item.key)} onChange={e => setSelectedAgents(current => e.target.checked ? [...current, item.key] : current.filter(key => key !== item.key))} /><span>{item.name}</span></label>)}</div>{agents.length === 0 && <p className="muted-copy">{tr(locale,"No agents detected.","未检测到智能体。")}</p>}</fieldset>}
        {needsAgent && <label className="field-label">{tr(locale,"Agent","智能体")}<select className="qise-input" value={agent} onChange={e => setAgent(e.target.value)}>{(agents.length ? agents : [{key:"codex",name:"Codex"}]).map(item => <option key={item.key} value={item.key}>{item.name}</option>)}</select></label>}
        {needsPath && <label className="field-label">{tr(locale, "File or directory path", "文件或目录路径")}<input className="qise-input" value={path} onChange={e => setPath(e.target.value)} placeholder={mode === "skill" ? "/path/to/skill" : "/path/to/mcp.json"} /></label>}
        {(mode === "all" || mode === "agent") && <fieldset><legend>{tr(locale,"Check categories","检查类别")}</legend><div className="scan-categories">{[[includeSkills,setIncludeSkills,tr(locale,"Skills","技能")],[includeMcp,setIncludeMcp,"MCP"],[includeAgentConfig,setIncludeAgentConfig,tr(locale,"Configuration","配置")]].map(([checked, setter, label]) => <label className="qise-check" key={String(label)}><input type="checkbox" checked={Boolean(checked)} onChange={e => (setter as (value:boolean)=>void)(e.target.checked)} /><span>{String(label)}</span></label>)}</div></fieldset>}
        <p className="scan-help">{tr(locale,"A check reviews your setup. It does not enable runtime protection.","体检只检查现有配置，不会自动开启运行时保护。")}</p>
      </div><div className="workspace-panel-footer"><BusyButton busy={busy} disabled={canRun || (mode === "all" && selectedAgents.length === 0)} onClick={() => {setResultPage(0);runScan();}} locale={locale}>{tr(locale,"Start safety check","开始安全体检")}</BusyButton><span className="subtle-label">{tr(locale,"Runs locally","在本地执行")}</span></div>
    </section>
    <section className="workspace-panel scan-results"><div className="workspace-panel-header"><h2>{tr(locale,"Check results","检查结果")}</h2><span className="subtle-label">{tr(locale,"02 / REVIEW","02 / 查看")}</span></div>
      {!report ? <div className="empty-workspace"><span className="empty-icon"><Icon name="scan" size={32} /></span><h3>{busy ? tr(locale,"Checking your setup…","正在检查配置…") : task.status === "failed" ? tr(locale,"Check could not complete","检查未完成") : tr(locale,"No check results yet","等待检查")}</h3><p>{task.error || tr(locale,"Choose what to check on the left. Results and evidence will appear here.","在左侧选择检查对象，结果与证据会显示在这里。")}</p>{busy && <Spinner tone="blue" />}</div>
      : <><div className="scan-summary"><span>{summary.reports} {tr(locale,"reports","份报告")}</span><span className="text-qise-red">{summary.block} {tr(locale,"blocked","项拦截")}</span><span>{summary.warn} {tr(locale,"warnings","项提醒")}</span><span>{scanFindingCount(report)} {tr(locale,"findings","个发现")}</span></div><div className="qise-tabs"><button className={`qise-tab ${resultTab === "reports" ? "is-active" : ""}`} onClick={() => setResultTab("reports")}>{tr(locale,"Reports","报告")}</button><button className={`qise-tab ${resultTab === "skipped" ? "is-active" : ""}`} onClick={() => setResultTab("skipped")}>{tr(locale,"Skipped","已跳过")} ({summary.skipped})</button></div>
      <div className="scan-report-detail">{resultTab === "reports" ? selectedReport ? <><div className="report-title"><span className={badgeClass(selectedReport.verdict)}>{verdictLabel(locale,selectedReport.verdict || "pass")}</span><span>{selectedReport.target_type}</span></div><h3>{selectedReport.target}</h3><p>{selectedReport.recommendation || report.recommendation}</p>{(selectedReport.findings ?? []).map((finding,i) => <div className="report-finding" key={i}><strong>{finding.message}</strong><code>{finding.path || finding.rule_id}</code>{finding.snippet && <pre>{finding.snippet}</pre>}</div>)}</> : <p>{tr(locale,"No findings.","没有发现项。")}</p> : isScanCollection(report) ? (report.skipped ?? []).map((item,i) => <p key={i}>{item.agent} · {item.target_type}<br/>{item.reason}</p>) : <p>{tr(locale,"No skipped items.","没有跳过的项目。")}</p>}</div>
      <div className="workspace-panel-footer"><span className="subtle-label">{reports.length ? reportIndex+1 : 0} / {reports.length}</span><div className="pager-buttons"><button disabled={reportIndex === 0} onClick={() => setResultPage(reportIndex-1)}>{tr(locale,"Previous","上一份")}</button><button disabled={reportIndex >= reports.length-1} onClick={() => setResultPage(reportIndex+1)}>{tr(locale,"Next","下一份")}</button></div></div></>}
    </section>
  </div>;
}

function EventsPage({ events, onEvent, locale }: { events: SecurityEvent[]; onEvent: (event: SecurityEvent) => void; locale: Locale }) {
  const [copied, setCopied] = useState(false);
  async function exportJson() {
    await copyText(JSON.stringify(events, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="page-stack events-workspace">
      <div className="list-toolbar">
        <button className="qise-action qise-action-secondary" onClick={exportJson}>
          {copied ? tr(locale, "Copied JSON", "已复制 JSON") : tr(locale, "Export JSON", "导出 JSON")}
        </button>
      </div>
      <div className="fill-panel"><EventLog events={events} onEvent={onEvent} locale={locale} /></div>
    </section>
  );
}

function RulesPage({
  guards,
  loadError,
  onSetGuardMode,
  setError,
  locale,
}: {
  guards: GuardInfo[];
  loadError: string | null;
  onSetGuardMode: (guardName: string, mode: string) => Promise<void>;
  setError: (error: string | null) => void;
  locale: Locale;
}) {
  const [busyPreset, setBusyPreset] = useState<GuardPreset | null>(null);

  async function applyPreset(preset: GuardPreset) {
    setBusyPreset(preset);
    setError(null);
    try {
      const modes = GUARD_PRESETS[preset];
      for (const guard of guards) {
        const mode = modes[guard.name];
        if (mode && mode !== guard.mode) {
          await onSetGuardMode(guard.name, mode);
        }
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusyPreset(null);
    }
  }

  return (
    <div className="page-stack rules-workspace">
      <div className="rules-preset-bar">
        <div>
          <h3>{tr(locale, "Global Presets", "全局预设")}</h3>
          <p>{tr(locale, "Changes are saved and apply to the next check, including after a restart.", "调整会保存，并从下一次检查开始生效；重启后仍会保留。")}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {(["balanced", "strict", "observe"] as GuardPreset[]).map((preset) => (
            <BusyButton
              key={preset}
              variant="secondary"
              busy={busyPreset === preset}
              busyLabel={tr(locale, "Applying...", "正在应用...")}
              disabled={busyPreset !== null || guards.length === 0}
              onClick={() => applyPreset(preset)}
              locale={locale}
            >
              {preset === "balanced"
                ? tr(locale, "Smart Protection", "智能保护")
                : preset === "strict"
                  ? tr(locale, "Strict", "严格")
                  : modeLabel(locale, preset)}
            </BusyButton>
          ))}
        </div>
      </div>
      {loadError && <p role="alert" className="qise-card p-4 text-sm text-qise-red">{loadError}</p>}
      {!loadError && guards.length === 0 && (
        <p className="qise-card p-4 text-sm text-[var(--text-tertiary)]">{tr(locale, "No protection rules loaded.", "尚未加载防护规则。")}</p>
      )}
      <div className="fill-panel"><GuardList guards={guards} onSetMode={onSetGuardMode} locale={locale} /></div>
    </div>
  );
}

function SlmPage({
  status,
  task,
  onStartSlm,
  onStopSlm,
  onCheckSlm,
  locale,
}: {
  status: AppStatus | null;
  task: TaskState<string>;
  onStartSlm: (request: SlmStartRequest) => void;
  onStopSlm: (keepServer: boolean) => void;
  onCheckSlm: () => void;
  locale: Locale;
}) {
  const [tab, setTab] = useState("connection");
  const [model, setModel] = useState(status?.slm?.model || "");
  const [baseUrl, setBaseUrl] = useState(status?.slm?.base_url || "http://localhost:11434/v1");
  const [apiKey, setApiKey] = useState("");
  const [timeoutMs, setTimeoutMs] = useState(10000);
  const [noInstall, setNoInstall] = useState(false);
  const [noPull, setNoPull] = useState(false);
  const [noVerify, setNoVerify] = useState(false);
  const [keepServer, setKeepServer] = useState(true);
  const busy = task.status === "running";
  const output = task.status === "failed" ? task.error : task.result;

  return <div className="workspace-split model-workspace">
    <section className="workspace-panel"><div className="qise-tabs"><button className={`qise-tab ${tab === "connection" ? "is-active" : ""}`} onClick={() => setTab("connection")}>{tr(locale,"Model connection","模型连接")}</button><button className={`qise-tab ${tab === "advanced" ? "is-active" : ""}`} onClick={() => setTab("advanced")}>{tr(locale,"Advanced options","高级选项")}</button></div>
      <div className="workspace-panel-body model-form">{tab === "connection" ? <><p className="muted-copy">{tr(locale,"Add optional model review. Setup may install Ollama and download your chosen model.","添加可选的模型审查。首次设置可能安装 Ollama 并下载所选模型。")}</p><label className="field-label">{tr(locale,"Service URL","服务地址")}<input className="qise-input" value={baseUrl} onChange={e => setBaseUrl(e.target.value)} /></label><label className="field-label">{tr(locale,"Model name","模型名称")}<input className="qise-input" value={model} onChange={e => setModel(e.target.value)} placeholder="qwen3:4b" /></label><label className="field-label">{tr(locale,"API key · optional","接口密钥 · 可选")}<input className="qise-input" type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder={tr(locale,"Leave empty for local models","本地模型可留空")} /></label></>
      : <><label className="field-label">{tr(locale,"Timeout (ms)","超时（毫秒）")}<input className="qise-input" type="number" value={timeoutMs} onChange={e => setTimeoutMs(Number(e.target.value) || 10000)} /></label><fieldset><legend>{tr(locale,"Setup behavior","安装行为")}</legend><label className="qise-check"><input type="checkbox" checked={noInstall} onChange={e=>setNoInstall(e.target.checked)} /><span>{tr(locale,"Skip automatic Ollama installation","跳过自动安装 Ollama")}</span></label><label className="qise-check"><input type="checkbox" checked={noPull} onChange={e=>setNoPull(e.target.checked)} /><span>{tr(locale,"Skip model download","跳过自动下载模型")}</span></label><label className="qise-check"><input type="checkbox" checked={noVerify} onChange={e=>setNoVerify(e.target.checked)} /><span>{tr(locale,"Save configuration without verification","不验证，直接写入配置")}</span></label><label className="qise-check"><input type="checkbox" checked={keepServer} onChange={e=>setKeepServer(e.target.checked)} /><span>{tr(locale,"Keep model server running when disabled","停用检测时保持模型服务运行")}</span></label></fieldset></>}</div>
      <div className="workspace-panel-footer"><BusyButton busy={busy && task.action === "start"} disabled={busy || !model.trim() || !baseUrl.trim()} onClick={() => onStartSlm({model,baseUrl,apiKey,timeoutMs,noInstall,noPull,noVerify})} locale={locale}>{tr(locale,"Enable detection","启用增强检测")}</BusyButton><BusyButton variant="secondary" busy={busy && task.action === "stop"} disabled={busy} onClick={()=>onStopSlm(keepServer)} locale={locale}>{tr(locale,"Disable","停用")}</BusyButton></div>
    </section>
    <section className="workspace-panel"><div className="workspace-panel-header"><h2>{tr(locale,"Detection status","检测状态")}</h2><button className="icon-button" onClick={onCheckSlm} disabled={busy} aria-label={tr(locale,"Check status","检查状态")}><Icon name="refresh" size={16} /></button></div><div className="workspace-panel-body"><div className={`model-state ${slmTone(status) === "ready" ? "is-ready" : ""}`}><Icon name="model" size={28} /><span>{slmStatusLabel(locale, slmLabel(status))}</span></div><dl className="detail-list"><div><dt>{tr(locale,"Provider","提供方")}</dt><dd>{status?.slm?.provider || "—"}</dd></div><div><dt>{tr(locale,"Model","模型")}</dt><dd>{status?.slm?.model || "—"}</dd></div><div><dt>{tr(locale,"Service","服务")}</dt><dd>{statusWord(locale,status?.slm?.server_running ? "running" : "not running")}</dd></div></dl><p className="inline-note">{tr(locale,"Model review supplements your local rules. Enabling it does not change guard policies.","模型审查补充本地规则，启用后不会自动改变守卫策略。")}</p></div>{(busy || output) && <pre className="code-output model-output" role="status">{busy ? task.title : output}</pre>}</section>
  </div>;
}

function App() {
  const [activePage, setActivePage] = useState<PageId>("home");
  const [locale, setLocale] = useState<Locale>(() => {
    const stored = window.localStorage.getItem("qise-locale");
    return stored === "zh" ? "zh" : "en";
  });
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [statusResolved, setStatusResolved] = useState(false);
  const [guards, setGuards] = useState<GuardInfo[]>([]);
  const [guardsError, setGuardsError] = useState<string | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [bootHintKey, setBootHintKey] = useState<"starting" | "checking" | "ready">("starting");
  const [lastError, setLastError] = useState<string | null>(null);
  const [detectingAgents, setDetectingAgents] = useState(false);
  const [stoppingProtection, setStoppingProtection] = useState(false);
  const [preflightTask, setPreflightTask] = useState<TaskState<ScanResult>>(() => createTask("Preflight Scan"));
  const [shieldTask, setShieldTask] = useState<TaskState<string>>(() => createTask("Agent Shield"));
  const [slmTask, setSlmTask] = useState<TaskState<string>>(() => createTask("Local SLM"));
  const statusInFlight = useRef(false);
  const bootHint = {
    starting: tr(locale, "Starting Qise runtime...", "正在启动 Qise 运行时..."),
    checking: tr(locale, "Still checking Qise. You can use the app while diagnostics finish.", "仍在检查 Qise。诊断完成前你也可以继续使用应用。"),
    ready: tr(locale, "Qise is ready.", "Qise 已就绪。"),
  }[bootHintKey];
  const appUpdater = useAppUpdater(
    {
      known: statusResolved && status !== null,
      enabled: status === null || statusProtectionEnabled(status) || statusHasConfiguredAgents(status),
    },
    statusResolved,
  );

  useEffect(() => {
    window.localStorage.setItem("qise-locale", locale);
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
    setPreflightTask((task) => task.status === "idle" ? createTask(tr(locale, "Preflight Scan", "上线前扫描")) : task);
    setShieldTask((task) => task.status === "idle" ? createTask(tr(locale, "Agent Shield", "智能体防护")) : task);
    setSlmTask((task) => task.status === "idle" ? createTask(tr(locale, "Local SLM", "本地小模型")) : task);
  }, [locale]);

  const loadStatus = useCallback(async () => {
    if (statusInFlight.current) return;
    statusInFlight.current = true;
    try {
      const nextStatus = normalizeStatus(await invoke<unknown>("get_status"));
      setStatus(nextStatus);
      if (nextStatus.detected_agents) {
        setAgents(nextStatus.detected_agents);
      }
    } catch (e) {
      setStatus(null);
      setAgents((previous) => previous.map((agent) => ({
        ...agent,
        protected: false,
        protection_status: agent.configured ? "needs_attention" : "not_protected",
      })));
      setLastError(String(e));
    } finally {
      statusInFlight.current = false;
      setStatusResolved(true);
      setBootHintKey("ready");
      setLoading(false);
    }
  }, []);

  const loadGuards = useCallback(async () => {
    try {
      const nextGuards = await invoke<GuardInfo[]>("get_guards");
      setGuards(nextGuards);
      setGuardsError(null);
    } catch (e) {
      setGuards([]);
      setGuardsError(String(e));
      setLastError(String(e));
    }
  }, []);

  const loadEvents = useCallback(async () => {
    try {
      const nextEvents = await invoke<unknown[]>("get_events", { limit: 100 });
      setEvents(nextEvents.map(normalizeSecurityEvent));
    } catch (e) {
      setLastError(String(e));
    }
  }, []);

  useEffect(() => {
    const bootTimer = setTimeout(() => {
      setBootHintKey("checking");
      setLoading(false);
    }, 3500);

    loadStatus();
    loadEvents();
    const detailTimer = setTimeout(loadGuards, 1200);
    const interval = setInterval(loadStatus, 15000);

    return () => {
      clearTimeout(bootTimer);
      clearTimeout(detailTimer);
      clearInterval(interval);
    };
  }, [loadEvents, loadGuards, loadStatus]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    listen<boolean>("toggle-protection", async (event) => {
      if (event.payload) {
        setActivePage("shield");
      } else {
        await stopProtection();
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const handleEvent = useCallback((event: SecurityEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, 100));
  }, []);

  async function refreshAll() {
    await Promise.all([loadStatus(), loadEvents(), loadGuards()]);
  }

  async function detectAgentsNow() {
    setDetectingAgents(true);
    setLastError(null);
    try {
      const detected = await invoke<unknown[]>("detect_agents");
      setAgents(detected.map(normalizeAgentInfo));
      await loadStatus();
    } catch (e) {
      setLastError(String(e));
    } finally {
      setDetectingAgents(false);
    }
  }

  async function stopProtection() {
    setStoppingProtection(true);
    try {
      await invoke("toggle_protection", { enable: false });
      await refreshAll();
    } catch (e) {
      setLastError(String(e));
    } finally {
      setStoppingProtection(false);
    }
  }

  async function handleSetGuardMode(guardName: string, mode: string) {
    try {
      await invoke("set_guard_mode", { guardName, mode });
      await loadGuards();
    } catch (e) {
      setLastError(String(e));
      throw e;
    }
  }

  function runQuickScan() {
    setActivePage("preflight");
    runPreflightScan({
      mode: "all", path: "", agent: "", selectedAgents: [],
      includeSkills: true, includeMcp: true, includeAgentConfig: true,
    });
  }

  function runPreflightScan(request: PreflightRequest) {
    const title = request.mode === "all"
      ? tr(locale, "Scanning selected agents", "正在扫描所选智能体")
      : request.mode === "agent"
        ? tr(locale, `Scanning ${request.agent}`, `正在扫描 ${request.agent}`)
        : tr(locale, `Scanning ${request.mode}`, `正在扫描${request.mode === "skill" ? "技能" : request.mode === "mcp" ? "协议服务" : "智能体配置"}`);
    const task = runningTask<ScanResult>(
      title,
      tr(locale, "Collecting agent config, skills and MCP evidence through the Qise CLI.", "正在通过 Qise 命令行收集智能体配置、技能与协议服务证据。"),
      "scan",
    );
    setPreflightTask(task);
    setLastError(null);

    void (async () => {
      try {
        const result = request.mode === "all"
          ? await invoke<ScanCollection>("scan_all_agents", {
              agents: request.selectedAgents,
              includeMissing: false,
              includeSkills: request.includeSkills,
              includeMcp: request.includeMcp,
              includeAgentConfig: request.includeAgentConfig,
            })
          : request.mode === "agent"
            ? await invoke<ScanCollection>("scan_agent_assets", {
                agent: request.agent,
                includeSkills: request.includeSkills,
                includeMcp: request.includeMcp,
                includeAgentConfig: request.includeAgentConfig,
              })
            : request.mode === "skill"
              ? await invoke<ScanReport>("scan_skill", { path: request.path })
              : request.mode === "mcp"
                ? await invoke<ScanReport>("scan_mcp", { path: request.path })
                : await invoke<ScanReport>("scan_agent_config", { agent: request.agent });
        setPreflightTask(succeededTask(task, result, tr(locale, "Scan finished. Results are preserved here until the next scan.", "扫描完成。结果会保留到下一次扫描。")));
        await loadEvents();
      } catch (e) {
        const failed = failedTask(task, e);
        setPreflightTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function runShieldAction(action: string, title: string, detail: string, operation: () => Promise<string>) {
    const task = runningTask<string>(title, detail, action);
    setShieldTask(task);
    setLastError(null);
    void (async () => {
      try {
        const output = await operation();
        setShieldTask(succeededTask(task, output, tr(locale, "Operation finished. You can review the output below.", "操作完成。你可以在下方查看输出。")));
        await refreshAll();
      } catch (e) {
        const failed = failedTask(task, e);
        setShieldTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function protectAgent(agent: AgentInfo, baseUrl: string) {
    runShieldAction(
      `protect:${agent.key}`,
      tr(locale, `Protecting ${agent.name}`, `正在保护 ${agent.name}`),
      agent.key === "claude-code"
        ? tr(locale, "Routing Claude Code through Qise's Anthropic Messages proxy.", "正在将 Claude Code 接入 Qise 的 Anthropic Messages 代理。")
        : tr(locale, "Patching agent config and starting Qise managed services.", "正在修改智能体配置并启动 Qise 管理的服务。"),
      async () => {
        const result = await invoke<CommandText>("protect_agent_with_options", {
          agent: agent.key,
          baseUrl,
          experimental: agent.experimental,
        });
        return requireCommandSuccess(result);
      },
    );
  }

  function restoreAgentTask(agent: AgentInfo) {
    runShieldAction(
      `restore:${agent.key}`,
      tr(locale, `Restoring ${agent.name}`, `正在恢复 ${agent.name}`),
      tr(locale, "Restoring the agent config from the latest Qise backup.", "正在从最新 Qise 备份恢复智能体配置。"),
      async () => {
        await invoke("restore_agent", { agent: agent.key });
        return tr(locale, `${agent.name} config restored.`, `${agent.name} 配置已恢复。`);
      },
    );
  }

  function restoreAllAgentsTask() {
    if (!window.confirm(tr(locale, "Restore all agent configs modified by Qise?", "恢复所有被 Qise 修改过的智能体配置？"))) return;
    runShieldAction("restore-all", tr(locale, "Restoring all agents", "正在恢复全部智能体"), tr(locale, "Restoring all configs modified by Qise.", "正在恢复全部由 Qise 修改过的配置。"), async () => {
      const result = await invoke<CommandText>("restore_all_agents");
      return requireCommandSuccess(result);
    });
  }

  function stopServicesTask() {
    runShieldAction("stop", tr(locale, "Stopping Qise services", "正在停止 Qise 服务"), tr(locale, "Stopping Qise managed proxy and bridge services.", "正在停止 Qise 管理的代理与桥接服务。"), async () => {
      const result = await invoke<CommandText>("stop_qise_services");
      return requireCommandSuccess(result);
    });
  }

  function protectCustomAgentTask(baseUrl: string) {
    if (!baseUrl.trim()) {
      setLastError(tr(locale, "Custom agent requires an upstream base URL.", "自定义智能体需要上游基础地址。"));
      return;
    }
    runShieldAction("protect:custom", tr(locale, "Protecting custom agent", "正在保护自定义智能体"), tr(locale, "Starting Qise proxy for the custom upstream.", "正在为自定义上游启动 Qise 代理。"), async () => {
      const result = await invoke<CommandText>("protect_agent_with_options", {
        agent: "custom",
        baseUrl,
        experimental: false,
      });
      return requireCommandSuccess(result);
    });
  }

  function runSlmAction(action: string, title: string, detail: string, operation: () => Promise<string>) {
    const task = runningTask<string>(title, detail, action);
    setSlmTask(task);
    setLastError(null);
    void (async () => {
      try {
        const output = await operation();
        setSlmTask(succeededTask(task, output, tr(locale, "SLM operation finished. Output is preserved here.", "小模型操作完成。输出会保留在这里。")));
        await refreshAll();
      } catch (e) {
        const failed = failedTask(task, e);
        setSlmTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function startSlmTask(request: SlmStartRequest) {
    runSlmAction("start", tr(locale, "Starting Local SLM", "正在启动本地小模型"), tr(locale, "Configuring the SLM layer through the Qise CLI.", "正在通过 Qise 命令行配置小模型层。"), async () => {
      const result = await invoke<CommandText>("slm_start", { ...request });
      return requireCommandSuccess(result);
    });
  }

  function stopSlmTask(keepServer: boolean) {
    runSlmAction("stop", tr(locale, "Stopping Local SLM", "正在停止本地小模型"), tr(locale, "Disabling Qise SLM config.", "正在禁用 Qise 小模型配置。"), async () => {
      const result = await invoke<CommandText>("slm_stop", { keepServer });
      return requireCommandSuccess(result);
    });
  }

  function checkSlmTask() {
    runSlmAction("status", tr(locale, "Checking Local SLM", "正在检查本地小模型"), tr(locale, "Reading SLM status from the Qise CLI.", "正在从 Qise 命令行读取小模型状态。"), async () => {
      const result = await invoke<unknown>("get_slm_status");
      return resultText(result);
    });
  }

  const pageTitleRight = useMemo(() => {
    if (activePage === "shield" && statusProtectionEnabled(status)) {
      return (
        <BusyButton locale={locale} variant="secondary" busy={stoppingProtection} busyLabel={tr(locale, "Stopping...", "正在停止...")} onClick={stopProtection}>
          {tr(locale, "Stop Protection", "停止保护")}
        </BusyButton>
      );
    }
    return null;
  }, [activePage, locale, status, stoppingProtection]);

  if (loading) {
    return <BootScreen hint={bootHint} locale={locale} />;
  }

  return (
    <DesktopShell page={activePage} onOpen={setActivePage} locale={locale}
      onToggleLocale={() => setLocale(current => current === "en" ? "zh" : "en")}
      status={status} version={appUpdater.state.currentVersion}
      actions={<>{activePage === "shield" && <BusyButton variant="secondary" busy={detectingAgents} onClick={detectAgentsNow} locale={locale}>{tr(locale, "Detect agents", "检测智能体")}</BusyButton>}{pageTitleRight}</>}
      notices={<><ErrorBanner error={lastError} onDismiss={() => setLastError(null)} locale={locale} /><TaskStrip tasks={[preflightTask, shieldTask, slmTask]} locale={locale} /></>}
    >
        {activePage === "tools" && <ToolsPage onOpen={setActivePage} locale={locale} />}
        {activePage === "home" && (
          <HomePage
            status={status}
            guards={guards}
            agents={agents}
            onOpen={setActivePage}
            onDetectAgents={detectAgentsNow}
            onQuickScan={runQuickScan}
            detectingAgents={detectingAgents}
            scanning={preflightTask.status === "running"}
            locale={locale}
          />
        )}
        {activePage === "shield" && (
          <AgentShieldPage
            agents={agents}
            task={shieldTask}
            onProtectAgent={protectAgent}
            onRestoreAgent={restoreAgentTask}
            onRestoreAll={restoreAllAgentsTask}
            onStopServices={stopServicesTask}
            onProtectCustom={protectCustomAgentTask}
            locale={locale}
          />
        )}
        {activePage === "preflight" && (
          <PreflightPage agents={agents} setError={setLastError} task={preflightTask} onRunScan={runPreflightScan} locale={locale} />
        )}
        {activePage === "events" && <EventsPage events={events} onEvent={handleEvent} locale={locale} />}
        {activePage === "rules" && (
          <RulesPage guards={guards} loadError={guardsError} onSetGuardMode={handleSetGuardMode} setError={setLastError} locale={locale} />
        )}
        {activePage === "slm" && (
          <SlmPage status={status} task={slmTask} onStartSlm={startSlmTask} onStopSlm={stopSlmTask} onCheckSlm={checkSlmTask} locale={locale} />
        )}
        {activePage === "doctor" && <DiagnosticsPanel locale={locale} />}
        {activePage === "observer" && <ObserverPage events={events} locale={locale} />}
        {activePage === "backup" && <BackupRestorePage status={status} onRefresh={refreshAll} setError={setLastError} locale={locale} />}
        {activePage === "integrations" && <IntegrationsPage setError={setLastError} locale={locale} />}
        {activePage === "advanced" && <AdvancedLabPage setError={setLastError} locale={locale} />}
        {activePage === "settings" && (
          <ConfigPanel
            locale={locale}
            updateState={appUpdater.state}
            onCheckForUpdates={appUpdater.checkForUpdates}
          />
        )}
    </DesktopShell>
  );
}

export default App;
