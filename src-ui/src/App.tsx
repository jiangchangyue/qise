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
import appIcon from "../../src-tauri/icons/icon.png";
import {
  AgentInfo,
  AppStatus,
  GuardInfo,
  ProtectedAgentRecord,
  SecurityEvent,
  agentStatus,
  normalizeAgentInfo,
  normalizeSecurityEvent,
  normalizeStatus,
  slmLabel,
  slmTone,
  statusEventCounts,
  statusHasConfiguredAgents,
  statusProtectionEnabled,
} from "./lib/api";
import {
  agentStatusLabel,
  modeLabel,
  pipelineLabel,
  portStatusLabel,
  slmStatusLabel,
  statusWord,
  tr,
  verdictLabel,
  type Locale,
} from "./lib/locale";

type PageId =
  | "home"
  | "shield"
  | "preflight"
  | "events"
  | "rules"
  | "slm"
  | "doctor"
  | "observer"
  | "backup"
  | "integrations"
  | "advanced"
  | "settings";

type ScanMode = "all" | "agent" | "skill" | "mcp" | "agent-config";
type GuardPreset = "balanced" | "strict" | "observe";
type Pipeline = "ingress" | "egress" | "output";

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

interface FeatureItem {
  id: PageId;
  glyph: string;
  title: Record<Locale, string>;
  subtitle: Record<Locale, string>;
  summary: Record<Locale, string>;
  accent: string;
}

const FEATURES: FeatureItem[] = [
  {
    id: "preflight",
    glyph: "PF",
    title: { en: "Safety Check", zh: "安全体检" },
    subtitle: { en: "Check your Agent setup", zh: "一键检查智能体风险" },
    summary: { en: "Skill, MCP and Agent config checks", zh: "检查技能、协议服务与智能体配置" },
    accent: "var(--qise-blue)",
  },
  {
    id: "shield",
    glyph: "AS",
    title: { en: "Smart Protection", zh: "智能保护" },
    subtitle: { en: "Protect your connected Agents", zh: "为已接入的智能体开启保护" },
    summary: { en: "Codex, OpenClaw, Claude Code, custom", zh: "支持 Codex、OpenClaw、Claude Code 与自定义智能体" },
    accent: "var(--qise-green)",
  },
  {
    id: "events",
    glyph: "EV",
    title: { en: "Security Events", zh: "安全事件" },
    subtitle: { en: "See what Qise blocked", zh: "查看 Qise 的拦截记录" },
    summary: { en: "Runtime and preflight evidence", zh: "运行时与上线前证据" },
    accent: "var(--qise-red)",
  },
  {
    id: "rules",
    glyph: "GR",
    title: { en: "Protection Rules", zh: "防护规则" },
    subtitle: { en: "Tune guard behavior", zh: "调整守卫行为" },
    summary: { en: "Ingress, egress and output guards", zh: "入口、出口与输出守卫" },
    accent: "var(--qise-yellow)",
  },
  {
    id: "slm",
    glyph: "AI",
    title: { en: "Enhanced Detection", zh: "增强检测（可选）" },
    subtitle: { en: "Optional model review", zh: "按需启用模型审查" },
    summary: { en: "Ollama or OpenAI-compatible model", zh: "支持 Ollama 或兼容接口模型" },
    accent: "var(--qise-blue)",
  },
  {
    id: "doctor",
    glyph: "DR",
    title: { en: "System Doctor", zh: "系统诊断" },
    subtitle: { en: "Check readiness", zh: "检查运行准备状态" },
    summary: { en: "Runtime, services and config checks", zh: "检查运行时、服务与配置" },
    accent: "var(--qise-green)",
  },
  {
    id: "observer",
    glyph: "RT",
    title: { en: "Runtime Observer", zh: "运行观察" },
    subtitle: { en: "Record real behavior", zh: "记录真实行为" },
    summary: { en: "Generate qise run commands", zh: "生成 qise run 命令" },
    accent: "var(--qise-yellow)",
  },
  {
    id: "backup",
    glyph: "BR",
    title: { en: "Backup & Restore", zh: "备份与恢复" },
    subtitle: { en: "Recover Agent configs", zh: "恢复智能体配置" },
    summary: { en: "View backups and restore safely", zh: "查看备份并安全恢复" },
    accent: "var(--qise-green)",
  },
  {
    id: "integrations",
    glyph: "IN",
    title: { en: "Integrations", zh: "集成" },
    subtitle: { en: "SDK, MCP and adapters", zh: "开发包、协议服务与适配器" },
    summary: { en: "Nanobot, Hermes, NexAU, LangGraph", zh: "Nanobot、Hermes、NexAU、LangGraph" },
    accent: "var(--qise-blue)",
  },
  {
    id: "settings",
    glyph: "CF",
    title: { en: "Settings", zh: "设置" },
    subtitle: { en: "App and model config", zh: "应用与模型配置" },
    summary: { en: "Proxy, upstream, SLM and guards", zh: "代理、上游、模型与守卫" },
    accent: "var(--text-tertiary)",
  },
  {
    id: "advanced",
    glyph: "LB",
    title: { en: "Advanced Lab", zh: "高级实验室" },
    subtitle: { en: "Test guards manually", zh: "手动测试守卫" },
    summary: { en: "check and context tools", zh: "检查与上下文工具" },
    accent: "var(--qise-red)",
  },
];

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

const ADAPTERS = ["nanobot", "hermes", "nexau", "langgraph", "openai-agents"] as const;

function featureTitle(item: FeatureItem, locale: Locale): string {
  return item.title[locale];
}

function featureSubtitle(item: FeatureItem, locale: Locale): string {
  return item.subtitle[locale];
}

function featureGlyph(item: FeatureItem, locale: Locale): string {
  if (locale === "en") return item.glyph;
  const glyphs: Partial<Record<PageId, string>> = {
    preflight: "扫",
    shield: "护",
    events: "事",
    rules: "规",
    slm: "模",
    doctor: "诊",
    observer: "观",
    backup: "备",
    integrations: "集",
    settings: "设",
    advanced: "实",
  };
  return glyphs[item.id] ?? item.glyph;
}

function scanGlyph(locale: Locale, en: string, zh: string): string {
  return locale === "zh" ? zh : en;
}

function eventVerdict(event: SecurityEvent): string {
  return event.decision.verdict || "pass";
}

function eventSummary(event: SecurityEvent): string {
  const evidence = event.evidence.find((item) => item.message || item.snippet);
  return evidence?.message || evidence?.snippet || event.recommendation || event.action.resource || event.risk.category;
}

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

function OperationPanel({
  title,
  detail,
  tone = "blue",
}: {
  title: string;
  detail?: string;
  tone?: "green" | "yellow" | "red" | "blue";
}) {
  return (
    <div className={`qise-operation qise-operation-${tone}`}>
      <div className="flex items-center gap-2">
        {tone === "blue" && <Spinner tone="blue" />}
        <p className="text-sm font-semibold text-[var(--text-primary)]">{title}</p>
      </div>
      {detail && <p className="mt-1 text-xs text-[var(--text-tertiary)]">{detail}</p>}
    </div>
  );
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
  const visible = tasks.filter((task) => task.status !== "idle");
  if (visible.length === 0) return null;
  return (
    <div className="qise-card mb-5 grid gap-2 p-3 md:grid-cols-3">
      {visible.map((task, index) => (
        <div key={`${task.title}-${index}`} className="rounded-lg bg-[var(--bg-card)] p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-sm font-semibold text-[var(--text-primary)]">{task.title}</p>
            <StatusPill tone={taskTone(task)}>{taskStatusText(task, locale)}</StatusPill>
          </div>
          <p className="mt-1 truncate text-xs text-[var(--text-tertiary)]">
            {task.status === "failed" ? task.error : task.detail || task.startedAt || ""}
          </p>
        </div>
      ))}
    </div>
  );
}

function BrandIcon({ locale }: { locale: Locale }) {
  return (
    <span className="qise-brand-icon" aria-label={tr(locale, "Qise app icon", "Qise 应用图标")}>
      <img src={appIcon} alt="" aria-hidden="true" />
    </span>
  );
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

function BootScreen({ hint, locale }: { hint: string; locale: Locale }) {
  return (
    <div className="min-h-screen bg-qise-deep px-5 pb-16 pt-4">
      <div className="mx-auto max-w-6xl">
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BrandIcon locale={locale} />
            <div>
              <h1 className="text-xl font-semibold text-[var(--text-primary)]">Qise</h1>
              <p className="text-sm text-[var(--text-tertiary)]">{tr(locale, "AI Agent Security", "智能体安全")}</p>
            </div>
          </div>
          <div className="flex gap-2">
            <div className="h-9 w-20 animate-pulse rounded-lg bg-[var(--bg-surface)]" />
            <div className="h-9 w-16 animate-pulse rounded-lg bg-[var(--bg-surface)]" />
          </div>
        </div>
        <div className="qise-hero mb-4 p-6">
          <div className="h-7 w-72 max-w-full animate-pulse rounded-xl bg-[var(--bg-card)]" />
          <div className="mt-4 h-4 w-[520px] max-w-full animate-pulse rounded bg-[var(--bg-card)]" />
          <p className="mt-5 text-sm text-[var(--text-tertiary)]">{hint}</p>
          <div className="mt-6 flex gap-3">
            <div className="h-10 w-36 animate-pulse rounded bg-[var(--bg-card)]" />
            <div className="h-10 w-28 animate-pulse rounded bg-[var(--bg-card)]" />
          </div>
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="qise-card h-24 animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <div key={index} className="qise-card h-24 animate-pulse" />
          ))}
        </div>
      </div>
    </div>
  );
}

function ErrorBanner({ error, onDismiss, locale }: { error: string | null; onDismiss: () => void; locale: Locale }) {
  if (!error) return null;
  return (
    <div className="qise-card mb-5 flex items-start justify-between gap-3 border-l-2 border-qise-red p-3">
      <p className="text-sm text-qise-red">{error}</p>
      <button
        className="shrink-0 rounded-[43px] bg-[var(--bg-card)] px-3 py-1 text-xs text-[var(--text-tertiary)]"
        onClick={onDismiss}
      >
        {tr(locale, "Dismiss", "关闭")}
      </button>
    </div>
  );
}

function PageHeader({
  page,
  onHome,
  right,
  locale,
}: {
  page: PageId;
  onHome: () => void;
  right?: ReactNode;
  locale: Locale;
}) {
  const feature = FEATURES.find((item) => item.id === page);
  if (page === "home") return null;
  return (
    <div className="qise-page-heading mb-5 flex flex-wrap items-center justify-between gap-3">
      <div className="flex min-w-0 items-center gap-3">
        <button className="qise-back-button" onClick={onHome} title={tr(locale, "Back to Home", "返回首页")}>
          <span aria-hidden="true">{"<-"}</span>
          <span>{tr(locale, "Back to Home", "返回首页")}</span>
        </button>
        <div className="h-7 w-px bg-[var(--border-subtle)]" />
        <div className="min-w-0">
          <h2 className="truncate text-xl font-semibold text-[var(--text-primary)]">
            {feature ? featureTitle(feature, locale) : ""}
          </h2>
          <p className="text-sm text-[var(--text-tertiary)]">{tr(locale, "Desktop Console", "桌面控制台")}</p>
        </div>
      </div>
      {right}
    </div>
  );
}

function MetricTile({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  tone?: "neutral" | "green" | "yellow" | "red" | "blue";
}) {
  const color = {
    neutral: "var(--text-tertiary)",
    green: "var(--qise-green)",
    yellow: "var(--qise-yellow)",
    red: "var(--qise-red)",
    blue: "var(--qise-blue)",
  }[tone];

  return (
    <div className="qise-metric-tile rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] px-3 py-2">
      <p className="qise-metric-label text-xs text-[var(--text-tertiary)]">{label}</p>
      <p className="qise-metric-value mt-1 font-mono text-lg font-semibold" style={{ color }} title={String(value)}>
        {value}
      </p>
    </div>
  );
}

function StatusFooter({
  status,
  version,
  locale,
}: {
  status: AppStatus | null;
  version: string;
  locale: Locale;
}) {
  return (
    <footer className="fixed bottom-0 left-0 right-0 z-40 border-t border-[var(--border-subtle)] bg-[rgba(243,248,252,0.94)] backdrop-blur">
      <div className="mx-auto grid max-w-6xl grid-cols-1 gap-2 px-5 py-2 text-xs text-[var(--text-tertiary)] sm:grid-cols-3">
        <span className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-qise-green" />
          {tr(locale, "Proxy", "代理")}：<span className="font-mono text-[var(--text-primary)]">{portStatusLabel(locale, status?.proxy, status?.proxy_port ?? 8822)}</span>
        </span>
        <span className="flex items-center justify-start gap-2 sm:justify-center">
          <span className="h-2 w-2 rounded-full bg-qise-yellow" />
          {tr(locale, "SLM", "小模型")}：<span className="font-mono text-[var(--text-primary)]">{slmStatusLabel(locale, slmLabel(status))}</span>
        </span>
        <span className="text-left sm:text-right">
          <span className="font-mono text-[var(--text-primary)]">
            {version ? `v${version}` : "-"}
          </span>
        </span>
      </div>
    </footer>
  );
}

function TopBar({
  activePage,
  status,
  onOpen,
  locale,
  onToggleLocale,
}: {
  activePage: PageId;
  status: AppStatus | null;
  onOpen: (page: PageId) => void;
  locale: Locale;
  onToggleLocale: () => void;
}) {
  const protectedEnabled = statusProtectionEnabled(status);
  return (
    <header className="qise-topbar mb-5 flex flex-wrap items-center justify-between gap-4">
      <button className="text-left" onClick={() => onOpen("home")}>
        <div className="flex items-center gap-3">
          <BrandIcon locale={locale} />
          <div>
            <h1 className="text-xl font-semibold leading-tight text-[var(--text-primary)]">Qise</h1>
            <p className="text-sm text-[var(--text-tertiary)]">{tr(locale, "AI Agent Security", "智能体安全")}</p>
          </div>
        </div>
      </button>
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill tone={protectedEnabled ? "green" : "yellow"}>
          {protectedEnabled ? tr(locale, "Protection ON", "保护已开启") : tr(locale, "Setup needed", "需要设置")}
        </StatusPill>
        <button
          className="qise-lang-button"
          onClick={onToggleLocale}
          title={tr(locale, "Switch language", "切换语言")}
          aria-label={tr(locale, "Switch language", "切换语言")}
        >
          <span className={locale === "en" ? "qise-lang-active" : ""}>EN</span>
          <span aria-hidden="true">/</span>
          <span className={locale === "zh" ? "qise-lang-active" : ""}>中文</span>
        </button>
        <button
          className={`qise-nav-button ${
            activePage === "doctor"
              ? "qise-nav-button-active"
              : ""
          }`}
          onClick={() => onOpen("doctor")}
        >
          {tr(locale, "Doctor", "诊断")}
        </button>
        <button
          className={`qise-nav-button ${
            activePage === "settings"
              ? "qise-nav-button-active"
              : ""
          }`}
          onClick={() => onOpen("settings")}
        >
          {tr(locale, "Settings", "设置")}
        </button>
      </div>
    </header>
  );
}

export function HomePage({
  status,
  guards,
  agents,
  onOpen,
  onDetectAgents,
  onQuickScan,
  detectingAgents,
  scanning,
  locale,
}: {
  status: AppStatus | null;
  guards: GuardInfo[];
  agents: AgentInfo[];
  onOpen: (page: PageId) => void;
  onDetectAgents: () => void;
  onQuickScan: () => void;
  detectingAgents: boolean;
  scanning: boolean;
  locale: Locale;
}) {
  const protectedEnabled = statusProtectionEnabled(status);
  const counts = statusEventCounts(status);
  const slmState = slmLabel(status);
  const slmStateTone = slmTone(status);
  const installedAgents = agents.filter((agent) => agent.installed || agent.configured);
  const protectedAgents = agents.filter((agent) => agent.protected);

  const featureBadges: Partial<Record<PageId, string>> = {
    events: `${counts.blocked}/${counts.warnings}`,
    rules: `${guards.length}`,
    slm: slmStatusLabel(locale, slmState),
    shield: `${protectedAgents.length}/${installedAgents.length || agents.length || 0}`,
    backup: `${Object.keys(status?.protected_agents ?? {}).length}`,
  };

  const STATUS_GLYPH = protectedEnabled ? "\u{1F6E1}" : "⚠";
  const needsAttention = statusHasConfiguredAgents(status) && !protectedEnabled;
  const servicesReady = status?.services_running === true;
  const mainStatus = !status
    ? tr(locale, "Checking protection status", "保护状态待确认")
    : protectedEnabled ? tr(locale, "Smart protection is on", "智能保护已开启")
      : needsAttention ? tr(locale, "Protection needs attention", "保护需要修复")
        : servicesReady ? tr(locale, "Services ready, awaiting connection", "服务已就绪，等待接入")
        : tr(locale, "Smart protection is off", "智能保护未开启");
  const statusDetail = protectedEnabled
    ? tr(locale, `${protectedAgents.length} agents protected · ${counts.blocked} blocks and ${counts.warnings} warnings in the last 24 hours`, `已保护 ${protectedAgents.length} 个智能体 · 近 24 小时拦截 ${counts.blocked} 次、提醒 ${counts.warnings} 次`)
    : needsAttention
      ? tr(locale, "A saved connection needs attention. Open Smart Protection to restore or reconnect it.", "已有接入配置需要处理。请打开智能保护，恢复原设置或重新接入。")
      : servicesReady
        ? tr(locale, "The local services are running. No supported agent route has been verified; manual connections need your own check.", "本地服务正在运行，尚未确认受支持的智能体接入；手动接入需自行检查路由。")
        : status?.services_running === false
          ? tr(locale, `Protection services are stopped · ${installedAgents.length} agents detected · Start with a safety check`, `保护服务已停止 · 已检测到 ${installedAgents.length} 个智能体 · 建议先做一次安全体检`)
          : tr(locale, `${installedAgents.length} agents detected · Start with a safety check`, `已检测到 ${installedAgents.length} 个智能体 · 建议先做一次安全体检`);

  const coreFeatures = FEATURES.filter((f) =>
    ["preflight", "shield", "events", "slm"].includes(f.id)
  );
  const moreFeatures = FEATURES.filter((f) =>
    ["rules", "doctor", "observer", "backup", "integrations", "advanced", "settings"].includes(f.id)
  );

  // Helper: feature card with icon + text
  function FeatureCardLarge({ item, badge }: { item: FeatureItem; badge?: string }) {
    const iconBg = `color-mix(in srgb, ${item.accent} 12%, white)`;
    return (
      <button
        className="qise-feature-card group"
        onClick={() => onOpen(item.id)}
      >
        <div
          className="qise-feature-icon shrink-0"
          style={{
            color: item.accent,
            backgroundColor: iconBg,
            border: `1px solid color-mix(in srgb, ${item.accent} 22%, white)`,
          }}
        >
          {featureGlyph(item, locale)}
        </div>
        <div className="qise-feature-card-body">
          <div className="qise-feature-card-title">{featureTitle(item, locale)}</div>
          <div className="qise-feature-card-subtitle">{featureSubtitle(item, locale)}</div>
        </div>
        {badge && (
          <span className="rounded-full bg-[var(--bg-card)] px-2 py-1 text-[11px] font-mono font-bold text-[var(--text-tertiary)] ring-1 ring-[var(--border-subtle)] shrink-0">
            {badge}
          </span>
        )}
      </button>
    );
  }

  return (
    <div className="space-y-5">
      {/* === STATUS BANNER === */}
      <section className={`qise-hero ${protectedEnabled ? "qise-hero-on" : "qise-hero-warn"}`}>
        <div className="flex flex-col gap-5 p-6 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 items-start gap-5">
            <div className={`qise-hero-icon ${protectedEnabled ? "qise-hero-icon-on" : "qise-hero-icon-warn"}`}>
              {STATUS_GLYPH}
            </div>
            <div className="min-w-0">
              <h2 className="text-3xl font-bold text-[var(--text-primary)]">{mainStatus}</h2>
              <p className="mt-2 text-base text-[var(--text-secondary)]">{statusDetail}</p>
              <p className="mt-2 text-sm text-[var(--text-dim)]">
                {protectedEnabled ? slmStateTone === "ready"
                  ? tr(locale, "The local-first guard pipeline is running with model review.", "本地优先的守卫流水线正在使用模型审查。")
                  : tr(locale, "Protection is running with local rules. Enhanced detection is optional.", "当前使用本地规则保护。增强检测可按需开启。")
                  : tr(locale, "A safety check reviews your setup. Runtime protection starts after an Agent is connected.", "安全体检会检查当前配置；接入智能体后才会开启运行时保护。")}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-3 md:justify-end">
            <BusyButton locale={locale} variant="primary" busy={scanning} busyLabel={tr(locale, "Checking...", "正在体检...")} onClick={onQuickScan}>
              {tr(locale, "Run Safety Check", "一键安全体检")}
            </BusyButton>
            <BusyButton locale={locale} variant="secondary" onClick={() => onOpen("shield")}>
              {tr(locale, "Smart Protection", "智能保护")}
            </BusyButton>
          </div>
        </div>
      </section>

      {/* === AGENT CARDS === */}
      <section>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="qise-section-label mb-0">{tr(locale, "Detected Agents", "已检测智能体")}</div>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">
              {tr(locale, "Agents detected on this device and existing connections that may need recovery.", "显示本机检测到的智能体，以及可能需要恢复的已有接入。")}
            </p>
          </div>
          <BusyButton locale={locale} variant="secondary" busy={detectingAgents} busyLabel={tr(locale, "Detecting...", "正在检测...")} onClick={onDetectAgents}>
            {tr(locale, "Detect Agents", "检测智能体")}
          </BusyButton>
        </div>
        {installedAgents.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-3">
            {installedAgents.map((agent) => {
            const dotClass = agent.protected ? "qise-agent-dot-green" : agent.installed ? "qise-agent-dot-yellow" : "qise-agent-dot-muted";
            const statusLabel = agentStatusLabel(locale, agentStatus(agent));

            return (
              <button key={agent.key} className="qise-agent-card group" onClick={() => onOpen("shield")}>
                <div className="flex items-center gap-4">
                  <span className={`qise-agent-dot ${dotClass}`} />
                  <div>
                    <p className="text-base font-semibold text-[var(--text-primary)]">{agent.name}</p>
                    <p className="text-sm text-[var(--text-secondary)]">{statusLabel}</p>
                  </div>
                </div>
                <StatusPill tone={agent.protected ? "green" : "yellow"}>
                  {agent.protected ? tr(locale, "Protected", "已保护") : tr(locale, "Detected", "已检测")}
                </StatusPill>
              </button>
            );
            })}
          </div>
        ) : (
          <div className="qise-card p-6 text-center">
            <p className="text-sm font-semibold text-[var(--text-primary)]">{tr(locale, "No supported agent detected yet.", "暂未检测到支持的智能体。")}</p>
            <p className="mt-2 text-sm text-[var(--text-tertiary)]">
              {tr(locale, "After installing or removing an agent, click Detect Agents to refresh this list.", "安装或删除智能体后，点击“检测智能体”即可刷新列表。")}
            </p>
          </div>
        )}
      </section>

      {/* === CORE FUNCTIONS === */}
      <section>
        <div className="qise-section-label">{tr(locale, "Core Protection", "核心防护")}</div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {coreFeatures.map((item) => (
            <FeatureCardLarge key={item.id} item={item} badge={featureBadges[item.id]} />
          ))}
        </div>
      </section>

      {/* === SUMMARY + MORE === */}
      <section className="grid gap-5 lg:grid-cols-[0.95fr_1.05fr]">
        <div>
          <div className="qise-section-label">{tr(locale, "Today's Summary", "今日摘要")}</div>
          <div className="qise-card grid gap-3 p-4 sm:grid-cols-4">
            <MetricTile label={tr(locale, "Protected", "已保护")} value={protectedAgents.length} tone={protectedEnabled ? "green" : "neutral"} />
            <MetricTile label={tr(locale, "Blocked", "已拦截")} value={counts.blocked} tone={counts.blocked > 0 ? "red" : "neutral"} />
            <MetricTile label={tr(locale, "Warnings", "告警")} value={counts.warnings} tone={counts.warnings > 0 ? "yellow" : "neutral"} />
            <MetricTile label={tr(locale, "SLM", "小模型")} value={slmStateTone === "ready" ? tr(locale, "ON", "开启") : slmStatusLabel(locale, slmState)} tone={slmStateTone === "ready" ? "green" : "yellow"} />
          </div>
        </div>

        <div>
          <div className="qise-section-label">{tr(locale, "More Tools", "更多工具")}</div>
          <div className="grid gap-3 sm:grid-cols-4">
            {moreFeatures.map((item) => (
              <button
                key={item.id}
                className="qise-card px-3 py-3 text-center text-xs font-semibold text-[var(--text-secondary)] hover:border-[var(--border-strong)]"
                onClick={() => onOpen(item.id)}
              >
                {featureTitle(item, locale)}
              </button>
            ))}
          </div>
        </div>
      </section>
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
  const [customBaseUrl, setCustomBaseUrl] = useState("");
  const busy = task.status === "running";
  const output = task.status === "failed" ? task.error : task.result;

  return (
    <div className="grid gap-5 xl:grid-cols-[1.35fr_0.65fr]">
      <section>
        <AgentPanel agents={agents} task={task} onProtect={onProtectAgent} onRestore={onRestoreAgent} locale={locale} />
      </section>
      <aside className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Shield Operations", "防护操作")}</h3>
          <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
            {tr(locale, "Protect patches the selected agent config to route through the Qise proxy and records a restorable backup.", "保护操作会修改所选智能体配置，使其经由 Qise 代理，并记录可恢复备份。")}
          </p>
          <div className="mt-4 space-y-2">
            <BusyButton locale={locale} className="w-full" variant="secondary" busy={busy && task.action === "restore-all"} busyLabel={tr(locale, "Restoring...", "正在恢复...")} disabled={busy} onClick={onRestoreAll}>
              {tr(locale, "Restore All Agents", "恢复全部智能体")}
            </BusyButton>
            <BusyButton locale={locale} className="w-full" variant="secondary" busy={busy && task.action === "stop"} busyLabel={tr(locale, "Stopping...", "正在停止...")} disabled={busy} onClick={onStopServices}>
              {tr(locale, "Stop Qise Services", "停止 Qise 服务")}
            </BusyButton>
          </div>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Custom Agent", "自定义智能体")}</h3>
          <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
            {tr(locale, "Route a custom OpenAI-compatible or Anthropic-native agent through Qise by providing its upstream base URL.", "提供上游基础地址后，可让自定义 OpenAI-compatible 或 Anthropic-native 智能体经由 Qise。")}
          </p>
          <label className="mt-3 block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Upstream base URL", "上游基础地址")}</span>
            <input
              className="qise-input"
              value={customBaseUrl}
              onChange={(event) => setCustomBaseUrl(event.target.value)}
              placeholder="https://api.example.com/v1"
            />
          </label>
          <BusyButton
            className="mt-4 w-full"
            busy={busy && task.action === "protect:custom"}
            busyLabel={tr(locale, "Protecting...", "正在保护...")}
            disabled={busy || !customBaseUrl.trim()}
            onClick={() => onProtectCustom(customBaseUrl)}
            locale={locale}
          >
            {tr(locale, "Protect Custom Agent", "保护自定义智能体")}
          </BusyButton>
        </div>
        {busy && (
          <OperationPanel title={task.title} detail={task.detail || tr(locale, "Qise is applying this operation in the background.", "Qise 正在后台执行此操作。")} />
        )}
        {!busy && output && (
          <pre className={`qise-card max-h-64 overflow-auto p-4 text-xs ${task.status === "failed" ? "text-qise-red" : "text-[var(--text-secondary)]"}`}>{output}</pre>
        )}
      </aside>
    </div>
  );
}

function BackupRestorePage({
  status,
  onRefresh,
  setError,
  locale,
}: {
  status: AppStatus | null;
  onRefresh: () => Promise<void>;
  setError: (error: string | null) => void;
  locale: Locale;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [output, setOutput] = useState("");
  const records = Object.entries(status?.protected_agents ?? {}) as [string, ProtectedAgentRecord][];

  async function restoreAgent(agent: string) {
    setBusy(agent);
    setError(null);
    try {
      await invoke("restore_agent", { agent });
      setOutput(tr(locale, `Restored ${agent}.`, `已恢复 ${agent}。`));
      await onRefresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function restoreAll() {
    if (!window.confirm(tr(locale, "Restore all agent configs modified by Qise?", "恢复所有被 Qise 修改过的智能体配置？"))) return;
    setBusy("all");
      setError(null);
    try {
      const result = await invoke<CommandText>("restore_all_agents");
      setOutput(requireCommandSuccess(result));
      await onRefresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
      <section className="qise-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
          <h3 className="text-xl font-semibold text-[var(--text-primary)]">{tr(locale, "Agent Config Backups", "智能体配置备份")}</h3>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">{tr(locale, "Qise keeps the original agent config before applying protection.", "Qise 会在启用保护前保存原始智能体配置。")}</p>
          </div>
          <BusyButton locale={locale} busy={busy === "all"} busyLabel={tr(locale, "Restoring...", "正在恢复...")} disabled={busy !== null || records.length === 0} onClick={restoreAll}>
            {tr(locale, "Restore All", "全部恢复")}
          </BusyButton>
        </div>
        <div className="mt-5 space-y-3">
          {records.length === 0 ? (
            <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">
              {tr(locale, "No protected agent backups found yet. Protect an agent first, then its backup will appear here.", "暂未发现受保护智能体的备份。先保护一个智能体后，备份会显示在这里。")}
            </p>
          ) : (
            records.map(([key, record]) => (
              <div key={key} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusPill tone="green">{tr(locale, "backup ready", "备份就绪")}</StatusPill>
                      <p className="font-semibold text-[var(--text-primary)]">{record.display_name || record.agent || key}</p>
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-[var(--text-tertiary)]">{record.config_path || tr(locale, "config path unavailable", "配置路径不可用")}</p>
                    <p className="mt-1 truncate font-mono text-xs text-[var(--text-dim)]">{record.backup_path || tr(locale, "backup path unavailable", "备份路径不可用")}</p>
                  </div>
                  <BusyButton
                    busy={busy === key}
                    busyLabel={tr(locale, "Restoring...", "正在恢复...")}
                    variant="secondary"
                    disabled={busy !== null}
                    onClick={() => restoreAgent(key)}
                    locale={locale}
                  >
                    {tr(locale, "Restore", "恢复")}
                  </BusyButton>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <aside className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Backup Directory", "备份目录")}</h3>
          <p className="mt-3 font-mono text-xs leading-5 text-[var(--text-secondary)]">~/.qise/backups/&lt;agent&gt;/&lt;timestamp&gt;/</p>
          <p className="mt-3 text-sm leading-6 text-[var(--text-tertiary)]">
            {tr(locale, "Restoring only touches agent config files previously changed by Qise. It does not remove your security events.", "恢复操作只会触碰曾被 Qise 修改的智能体配置文件，不会删除安全事件。")}
          </p>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Last Operation", "最近操作")}</h3>
          {busy ? (
            <OperationPanel title={tr(locale, "Restore command running...", "恢复命令运行中...")} detail={tr(locale, "Qise is applying the selected backup through the product CLI.", "Qise 正在通过命令行应用所选备份。")} />
          ) : (
            <pre className="max-h-64 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
              {output || tr(locale, "No restore operation has run in this session.", "本次会话尚未执行恢复操作。")}
            </pre>
          )}
        </div>
      </aside>
    </div>
  );
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

  return (
    <div className="space-y-4">
      <section className="qise-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xl font-semibold text-[var(--text-primary)]">{tr(locale, "What do you want to scan?", "你想扫描什么？")}</h3>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">{tr(locale, "Validate installed agents and integrations before enabling them.", "启用前验证已安装的智能体和集成。")}</p>
          </div>
          <StatusPill tone="green">{tr(locale, "Pre-install check", "安装前检查")}</StatusPill>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-3">
          {[
            { id: "all", title: tr(locale, "All Agents", "全部智能体"), subtitle: tr(locale, "One-click full scan", "一键完整扫描"), glyph: scanGlyph(locale, "ALL", "全") },
            { id: "agent", title: tr(locale, "Single Agent", "单个智能体"), subtitle: tr(locale, "Choose agent and categories", "选择智能体和类别"), glyph: scanGlyph(locale, "AG", "单") },
            { id: "agent-config", title: tr(locale, "Agent Config", "智能体配置"), subtitle: tr(locale, "Check installed config", "检查已安装配置"), glyph: scanGlyph(locale, "CFG", "配") },
            { id: "skill", title: tr(locale, "Skill Path", "技能路径"), subtitle: tr(locale, "Advanced manual scan", "高级手动扫描"), glyph: scanGlyph(locale, "SK", "技") },
            { id: "mcp", title: tr(locale, "MCP Path", "协议服务路径"), subtitle: tr(locale, "Advanced manual scan", "高级手动扫描"), glyph: scanGlyph(locale, "MCP", "协") },
          ].map((item) => (
            <button
              key={item.id}
              className={`qise-choice-card ${mode === item.id ? "qise-choice-card-active" : ""}`}
              onClick={() => setMode(item.id as ScanMode)}
            >
              <span className="qise-choice-icon">{item.glyph}</span>
              <span>
                <span className="block text-base font-semibold text-[var(--text-primary)]">{item.title}</span>
                <span className="block text-sm text-[var(--text-tertiary)]">{item.subtitle}</span>
              </span>
            </button>
          ))}
        </div>

        {(mode === "all" || mode === "agent") && (
          <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_1fr]">
            <div className="rounded-lg bg-[var(--bg-card)] p-4">
              <p className="mb-3 text-sm font-semibold text-[var(--text-primary)]">{tr(locale, "Agents", "智能体")}</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {(agents.length ? agents : [{ key: "codex", name: "Codex" } as AgentInfo]).map((item) => (
                  <label key={item.key} className="qise-check rounded-lg bg-white px-3 py-2">
                    <input
                      type="checkbox"
                      checked={mode === "agent" ? agent === item.key : selectedAgents.includes(item.key)}
                      onChange={(event) => {
                        if (mode === "agent") {
                          setAgent(item.key);
                          return;
                        }
                        setSelectedAgents((current) =>
                          event.target.checked
                            ? Array.from(new Set([...current, item.key]))
                            : current.filter((key) => key !== item.key),
                        );
                      }}
                    />
                    <span>{item.name}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="rounded-lg bg-[var(--bg-card)] p-4">
              <p className="mb-3 text-sm font-semibold text-[var(--text-primary)]">{tr(locale, "Categories", "类别")}</p>
              <div className="grid gap-2 sm:grid-cols-3">
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeSkills} onChange={(event) => setIncludeSkills(event.target.checked)} />
                  <span>{tr(locale, "Skills", "技能")}</span>
                </label>
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeMcp} onChange={(event) => setIncludeMcp(event.target.checked)} />
                  <span>{tr(locale, "MCP", "协议服务")}</span>
                </label>
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeAgentConfig} onChange={(event) => setIncludeAgentConfig(event.target.checked)} />
                  <span>{tr(locale, "Agent config", "智能体配置")}</span>
                </label>
              </div>
            </div>
          </div>
        )}

        {mode === "agent-config" && (
          <label className="mt-5 block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Agent config", "智能体配置")}</span>
            <select
              className="qise-input"
              value={agent}
              onChange={(event) => setAgent(event.target.value)}
            >
              {(agents.length ? agents : [{ key: "codex", name: "Codex" } as AgentInfo]).map((item) => (
                <option key={item.key} value={item.key}>{item.name}</option>
              ))}
            </select>
          </label>
        )}

        {needsPath && (
          <label className="mt-4 block">
            <span className="text-xs text-[var(--text-tertiary)]">
              {mode === "skill" ? tr(locale, "Skill directory or file path", "技能目录或文件路径") : tr(locale, "MCP JSON/YAML config path", "协议服务 JSON/YAML 配置路径")}
            </span>
            <input
              className="qise-input font-mono"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder={mode === "skill" ? "/path/to/skill" : "/path/to/mcp.json"}
            />
          </label>
        )}
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <BusyButton locale={locale} busy={busy} busyLabel={tr(locale, "Scanning...", "正在扫描...")} disabled={canRun} onClick={runScan}>
            {mode === "all" ? tr(locale, "Scan Selected Agents", "扫描所选智能体") : tr(locale, "Run Scan", "运行扫描")}
          </BusyButton>
          {busy && <p className="text-sm text-[var(--text-tertiary)]">{tr(locale, "Qise is running the preflight CLI in the background. You can return home and come back here.", "Qise 正在后台运行上线前扫描命令。你可以先返回首页，稍后再回到这里。")}</p>}
        </div>
      </section>

      <section className="qise-card p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Result", "结果")}</h3>
            <p className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Findings are also recorded as preflight security events.", "发现项也会记录为上线前安全事件。")}</p>
          </div>
          {report?.verdict && <span className={badgeClass(report.verdict)}>{verdictLabel(locale, report.verdict)}</span>}
        </div>
        {busy ? (
          <OperationPanel title={task.title || tr(locale, "Scanning agent assets...", "正在扫描智能体资产...")} detail={task.detail || tr(locale, "Checking selected agent files, MCP candidates and config state.", "正在检查所选智能体文件、协议服务候选项与配置状态。")} />
        ) : task.status === "failed" ? (
          <OperationPanel title={tr(locale, "Scan failed", "扫描失败")} detail={task.error} tone="red" />
        ) : !report ? (
          <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">{tr(locale, "Choose a target and run a scan.", "选择目标后运行扫描。")}</p>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
              <MetricTile label={tr(locale, "Reports", "报告")} value={summary.reports} tone="blue" />
              <MetricTile label={tr(locale, "Blocks", "拦截")} value={summary.block} tone={summary.block > 0 ? "red" : "neutral"} />
              <MetricTile label={tr(locale, "Warnings", "告警")} value={summary.warn} tone={summary.warn > 0 ? "yellow" : "neutral"} />
              <MetricTile label={tr(locale, "Findings", "发现项")} value={scanFindingCount(report)} tone={scanFindingCount(report) > 0 ? "yellow" : "green"} />
            </div>
            <p className="text-sm text-[var(--text-secondary)]">{report.recommendation}</p>
            <div className="grid gap-3 xl:grid-cols-2">
              {reports.length === 0 ? (
                <p className="rounded-lg bg-[var(--bg-card)] p-3 text-sm text-[var(--text-dim)]">{tr(locale, "No findings.", "没有发现项。")}</p>
              ) : (
                reports.map((item, reportIndex) => (
                  <div key={`${item.target}-${reportIndex}`} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={badgeClass(item.verdict)}>{item.verdict ? verdictLabel(locale, item.verdict) : tr(locale, "report", "报告")}</span>
                      <span className="text-xs font-mono text-[var(--text-secondary)]">{item.target_type}</span>
                      <span className="text-xs text-[var(--text-dim)]">{statusWord(locale, item.risk?.severity || "low")}</span>
                    </div>
                    <p className="mt-2 truncate text-sm font-mono text-[var(--text-secondary)]">{item.target}</p>
                    {(item.findings ?? []).slice(0, 3).map((finding, index) => (
                      <div key={`${finding.rule_id}-${index}`} className="mt-2 rounded bg-white p-2">
                        <p className="text-xs font-semibold text-[var(--text-secondary)]">{finding.message}</p>
                        {finding.path && <p className="mt-1 text-[11px] font-mono text-[var(--text-dim)]">{finding.path}</p>}
                      </div>
                    ))}
                    {(item.findings ?? []).length === 0 && (
                      <p className="mt-2 text-xs text-[var(--text-dim)]">{tr(locale, "No findings in this asset.", "该资产没有发现项。")}</p>
                    )}
                  </div>
                ))
              )}
            </div>
            {isScanCollection(report) && (report.skipped?.length ?? 0) > 0 && (
              <div className="rounded-lg bg-[var(--bg-card)] p-3">
                <p className="text-xs font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Skipped", "已跳过")}</p>
                {report.skipped?.map((item, index) => (
                  <p key={`${item.agent}-${item.target_type}-${index}`} className="mt-1 text-xs text-[var(--text-tertiary)]">
                    {item.agent} · {item.target_type}: {item.reason}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function EventsPage({ events, onEvent, locale }: { events: SecurityEvent[]; onEvent: (event: SecurityEvent) => void; locale: Locale }) {
  const [copied, setCopied] = useState(false);
  async function exportJson() {
    await copyText(JSON.stringify(events, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-end">
        <button className="rounded-[43px] bg-[var(--bg-card)] px-4 py-2 text-sm text-[var(--text-secondary)]" onClick={exportJson}>
          {copied ? tr(locale, "Copied JSON", "已复制 JSON") : tr(locale, "Export JSON", "导出 JSON")}
        </button>
      </div>
      <EventLog events={events} onEvent={onEvent} locale={locale} />
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
    <div className="space-y-5">
      <div className="qise-card flex flex-wrap items-center justify-between gap-4 p-4">
        <div>
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Global Presets", "全局预设")}</h3>
          <p className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Changes are saved and apply to the next check, including after a restart.", "调整会保存，并从下一次检查开始生效；重启后仍会保留。")}</p>
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
      <GuardList guards={guards} onSetMode={onSetGuardMode} locale={locale} />
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

  return (
    <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Quick Setup", "快速设置")}</h3>
        <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
          {tr(locale, "Enhanced detection is optional. Choose a model, then start setup when you are ready. Setup may install Ollama and download the model.", "增强检测是可选项。填写模型后，再按需启动设置；此操作可能安装 Ollama 并下载模型。")}
        </p>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Base URL", "基础地址")}</span>
            <input className="qise-input" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Model", "模型")}</span>
            <input className="qise-input" value={model} onChange={(event) => setModel(event.target.value)} placeholder="qwen3:4b" />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "API key", "接口密钥")}</span>
            <input className="qise-input" type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder={tr(locale, "Optional", "可选")} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Timeout ms", "超时毫秒")}</span>
            <input className="qise-input" type="number" value={timeoutMs} onChange={(event) => setTimeoutMs(Number(event.target.value) || 10000)} />
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noInstall} onChange={(event) => setNoInstall(event.target.checked)} />
            <span>{tr(locale, "Skip automatic Ollama install", "跳过自动安装 Ollama")}</span>
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noPull} onChange={(event) => setNoPull(event.target.checked)} />
            <span>{tr(locale, "Skip automatic model pull", "跳过自动拉取模型")}</span>
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noVerify} onChange={(event) => setNoVerify(event.target.checked)} />
            <span>{tr(locale, "Write config without verification", "不验证直接写入配置")}</span>
          </label>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <BusyButton
            busy={busy && task.action === "start"}
            busyLabel={tr(locale, "Starting...", "正在启动...")}
            disabled={busy || !model.trim() || !baseUrl.trim()}
            onClick={() => onStartSlm({ model, baseUrl, apiKey, timeoutMs, noInstall, noPull, noVerify })}
            locale={locale}
          >
            {tr(locale, "Start SLM", "启动小模型")}
          </BusyButton>
          <BusyButton locale={locale} variant="secondary" busy={busy && task.action === "stop"} busyLabel={tr(locale, "Stopping...", "正在停止...")} disabled={busy} onClick={() => onStopSlm(keepServer)}>
            {tr(locale, "Stop SLM", "停止小模型")}
          </BusyButton>
          <BusyButton locale={locale} variant="secondary" busy={busy && task.action === "status"} busyLabel={tr(locale, "Checking...", "正在检查...")} disabled={busy} onClick={onCheckSlm}>
            {tr(locale, "Check Status", "检查状态")}
          </BusyButton>
        </div>
        <label className="qise-check mt-4">
          <input type="checkbox" checked={keepServer} onChange={(event) => setKeepServer(event.target.checked)} />
          <span>{tr(locale, "Keep model server running when disabling Qise SLM", "禁用 Qise 小模型时保持模型服务运行")}</span>
        </label>
      </section>
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Current State", "当前状态")}</h3>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <MetricTile label={tr(locale, "Verification", "验证")} value={slmStatusLabel(locale, status?.slm?.verification || slmLabel(status))} tone={slmTone(status) === "ready" ? "green" : "yellow"} />
          <MetricTile label={tr(locale, "Provider", "提供方")} value={status?.slm?.provider || statusWord(locale, "none")} tone="blue" />
          <MetricTile label={tr(locale, "Model", "模型")} value={status?.slm?.model || statusWord(locale, "not_configured")} />
          <MetricTile label={tr(locale, "Server", "服务")} value={status?.slm?.server_running ? statusWord(locale, "running") : statusWord(locale, "not running")} tone={status?.slm?.server_running ? "green" : "neutral"} />
        </div>
        {busy && <OperationPanel title={task.title} detail={task.detail || tr(locale, "This runs in the background; you can leave this page and return.", "该操作会在后台运行；你可以离开本页后再回来查看。")} />}
        {!busy && output && (
          <pre className={`mt-4 max-h-80 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs ${task.status === "failed" ? "text-qise-red" : "text-[var(--text-secondary)]"}`}>
            {output}
          </pre>
        )}
      </section>
    </div>
  );
}

function ObserverPage({ events, locale }: { events: SecurityEvent[]; locale: Locale }) {
  const [agent, setAgent] = useState("codex");
  const [command, setCommand] = useState("codex");
  const [cwd, setCwd] = useState("");
  const [copied, setCopied] = useState(false);
  const runtimeEvents = events.filter((event) => event.stage === "runtime").slice(0, 8);
  const generated = `qise run --agent ${agent}${cwd ? ` --cwd ${cwd}` : ""} -- ${command}`;

  async function copyCommand() {
    await copyText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Command Builder", "命令构建器")}</h3>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Agent", "智能体")}</span>
            <input className="qise-input" value={agent} onChange={(event) => setAgent(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Command", "命令")}</span>
            <input className="qise-input" value={command} onChange={(event) => setCommand(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Working directory", "工作目录")}</span>
            <input className="qise-input" value={cwd} onChange={(event) => setCwd(event.target.value)} placeholder={tr(locale, "Optional", "可选")} />
          </label>
        </div>
        <pre className="mt-4 rounded-lg bg-[var(--bg-card)] p-3 text-xs text-[var(--text-secondary)]">{generated}</pre>
        <button className="mt-4 rounded-[43px] bg-[var(--button-primary-bg)] px-4 py-2 text-sm text-white" onClick={copyCommand}>
          {copied ? tr(locale, "Copied", "已复制") : tr(locale, "Copy Command", "复制命令")}
        </button>
      </section>
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Runtime Events", "运行时事件")}</h3>
        <div className="mt-4 space-y-2">
          {runtimeEvents.length === 0 ? (
            <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">{tr(locale, "No runtime events yet.", "暂无运行时事件。")}</p>
          ) : (
            runtimeEvents.map((event) => (
              <div key={event.id} className="rounded-lg bg-[var(--bg-card)] p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-mono text-[var(--text-dim)]">{event.timestamp.slice(0, 19).replace("T", " ")}</span>
                  <span className={badgeClass(eventVerdict(event))}>{verdictLabel(locale, eventVerdict(event))}</span>
                </div>
                <p className="mt-2 text-sm text-[var(--text-secondary)]">{eventSummary(event)}</p>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function IntegrationsPage({ setError, locale }: { setError: (error: string | null) => void; locale: Locale }) {
  const [adapter, setAdapter] = useState<(typeof ADAPTERS)[number]>("nanobot");
  const [snippet, setSnippet] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  async function loadSnippet(nextAdapter = adapter) {
    setBusy(true);
    setError(null);
    try {
      const text = await invoke<string>("get_adapter_snippet", { adapter: nextAdapter });
      setSnippet(text);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function copySnippet() {
    await copyText(snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.72fr_1.28fr]">
      <section className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Adapters", "适配器")}</h3>
          <div className="mt-4 space-y-2">
            {ADAPTERS.map((item) => (
              <button
                key={item}
                className={`w-full rounded-lg px-3 py-2 text-left text-sm ${adapter === item ? "bg-[var(--button-primary-bg)] text-white" : "bg-[var(--bg-card)] text-[var(--text-secondary)]"}`}
                onClick={() => {
                  setAdapter(item);
                  loadSnippet(item);
                }}
              >
                {item}
              </button>
            ))}
          </div>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Runtime Modes", "运行模式")}</h3>
          <div className="mt-3 space-y-2 text-xs text-[var(--text-secondary)]">
            <code className="block rounded bg-[var(--bg-card)] p-2">qise proxy start --upstream https://api.openai.com/v1</code>
            <code className="block rounded bg-[var(--bg-card)] p-2">qise proxy start --upstream https://api.anthropic.com</code>
            <code className="block rounded bg-[var(--bg-card)] p-2">qise bridge start</code>
            <code className="block rounded bg-[var(--bg-card)] p-2">qise serve --transport stdio</code>
          </div>
        </div>
      </section>
      <section className="qise-card p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Integration Snippet", "集成片段")}</h3>
            <p className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Generated from the product CLI.", "由产品命令行生成。")}</p>
          </div>
          <div className="flex gap-2">
            <BusyButton locale={locale} variant="secondary" busy={busy} busyLabel={tr(locale, "Loading...", "正在加载...")} onClick={() => loadSnippet()}>
              {tr(locale, "Load", "加载")}
            </BusyButton>
            <button className="rounded-[43px] bg-[var(--bg-card)] px-3 py-1 text-xs text-[var(--text-secondary)] disabled:opacity-50" disabled={!snippet} onClick={copySnippet}>
              {copied ? tr(locale, "Copied", "已复制") : tr(locale, "Copy", "复制")}
            </button>
          </div>
        </div>
        <pre className="max-h-[560px] overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
          {snippet || tr(locale, "Choose an adapter and load its snippet.", "选择适配器并加载集成片段。")}
        </pre>
      </section>
    </div>
  );
}

function AdvancedLabPage({ setError, locale }: { setError: (error: string | null) => void; locale: Locale }) {
  const [toolName, setToolName] = useState("bash");
  const [toolArgs, setToolArgs] = useState('{"command":"echo hello"}');
  const [pipeline, setPipeline] = useState<Pipeline>("egress");
  const [sessionId, setSessionId] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [context, setContext] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function runCheck() {
    setBusy("check");
    setError(null);
    try {
      JSON.parse(toolArgs);
      const value = await invoke<unknown>("run_check", {
        toolName,
        toolArgs,
        pipeline,
        sessionId,
      });
      setResult(value);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function loadContext() {
    setBusy("context");
    setError(null);
    try {
      if (toolArgs.trim()) JSON.parse(toolArgs);
      const value = await invoke<string>("get_context", { toolName, toolArgs });
      setContext(value || tr(locale, "No context generated.", "没有生成上下文。"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Guard Input", "守卫输入")}</h3>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Tool name", "工具名称")}</span>
            <input className="qise-input" value={toolName} onChange={(event) => setToolName(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Tool args JSON", "工具参数 JSON")}</span>
            <textarea className="qise-input min-h-32" value={toolArgs} onChange={(event) => setToolArgs(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Pipeline", "流水线")}</span>
            <select className="qise-input" value={pipeline} onChange={(event) => setPipeline(event.target.value as Pipeline)}>
              <option value="ingress">{pipelineLabel(locale, "ingress")}</option>
              <option value="egress">{pipelineLabel(locale, "egress")}</option>
              <option value="output">{pipelineLabel(locale, "output")}</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">{tr(locale, "Session ID", "会话编号")}</span>
            <input className="qise-input" value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder={tr(locale, "Optional", "可选")} />
          </label>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <BusyButton locale={locale} busy={busy === "check"} busyLabel={tr(locale, "Checking...", "正在检查...")} disabled={busy !== null} onClick={runCheck}>
            {tr(locale, "Run Check", "运行检查")}
          </BusyButton>
          <BusyButton locale={locale} variant="secondary" busy={busy === "context"} busyLabel={tr(locale, "Loading...", "正在加载...")} disabled={busy !== null} onClick={loadContext}>
            {tr(locale, "Get Context", "获取上下文")}
          </BusyButton>
        </div>
      </section>
      <section className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Check Result", "检查结果")}</h3>
          <pre className="mt-3 max-h-64 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
            {result ? resultText(result) : tr(locale, "Run a check to see guard verdicts.", "运行检查后查看守卫判定。")}
          </pre>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">{tr(locale, "Security Context", "安全上下文")}</h3>
          <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
            {context || tr(locale, "Get context to preview injected guidance.", "获取上下文以预览注入指引。")}
          </pre>
        </div>
      </section>
    </div>
  );
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
    <div className="min-h-screen bg-qise-deep px-5 pb-16 pt-5">
      <div className="mx-auto max-w-7xl">
        <TopBar
          activePage={activePage}
          status={status}
          onOpen={setActivePage}
          locale={locale}
          onToggleLocale={() => setLocale((current) => current === "en" ? "zh" : "en")}
        />
        <ErrorBanner error={lastError} onDismiss={() => setLastError(null)} locale={locale} />
        <TaskStrip tasks={[preflightTask, shieldTask, slmTask]} locale={locale} />
        <PageHeader page={activePage} onHome={() => setActivePage("home")} right={pageTitleRight} locale={locale} />

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
      </div>
      <StatusFooter status={status} version={appUpdater.state.currentVersion} locale={locale} />
    </div>
  );
}

export default App;
