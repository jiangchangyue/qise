import type { PortStatus } from "./api";

export type Locale = "en" | "zh";

export function tr(locale: Locale, en: string, zh: string): string {
  return locale === "zh" ? zh : en;
}

function statusKey(value?: string | null): string {
  return (value || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
}

export function statusWord(locale: Locale, value?: string | null): string {
  const normalized = statusKey(value);
  const labels: Record<string, [string, string]> = {
    unknown: ["unknown", "未知"],
    unavailable: ["unavailable", "不可用"],
    none: ["none", "无"],
    ready: ["ready", "就绪"],
    ok: ["ok", "正常"],
    available: ["available", "可用"],
    warning: ["warning", "警告"],
    warn: ["warning", "警告"],
    ready_with_warnings: ["ready with warnings", "就绪但有警告"],
    not_configured: ["not configured", "未配置"],
    busy: ["busy", "忙碌"],
    protected: ["protected", "已保护"],
    unprotected: ["unprotected", "未保护"],
    running: ["running", "运行中"],
    not_running: ["not running", "未运行"],
    local: ["local", "本地"],
    cloud: ["cloud", "云端"],
    pass: ["pass", "通过"],
    block: ["block", "拦截"],
    warn_verdict: ["warn", "告警"],
    observe: ["observe", "观察"],
    enforce: ["enforce", "拦截"],
    off: ["off", "关闭"],
    low: ["low", "低"],
    medium: ["medium", "中"],
    high: ["high", "高"],
  };

  if (normalized === "warn" && value === "warn") {
    return tr(locale, "warn", "告警");
  }

  const match = labels[normalized];
  if (match) return tr(locale, match[0], match[1]);
  return value || tr(locale, "unknown", "未知");
}

export function verdictLabel(locale: Locale, verdict?: string | null): string {
  const normalized = (verdict || "pass").toLowerCase();
  if (normalized === "block") return tr(locale, "block", "拦截");
  if (normalized === "warn") return tr(locale, "warn", "告警");
  if (normalized === "info") return tr(locale, "Info", "提示");
  return tr(locale, "pass", "通过");
}

export function modeLabel(locale: Locale, mode?: string | null): string {
  const normalized = (mode || "").toLowerCase();
  if (normalized === "observe") return tr(locale, "observe", "观察");
  if (normalized === "enforce") return tr(locale, "enforce", "拦截");
  if (normalized === "off") return tr(locale, "off", "关闭");
  return mode || tr(locale, "unknown", "未知");
}

export function pipelineLabel(locale: Locale, pipeline?: string | null): string {
  const normalized = (pipeline || "").toLowerCase();
  if (normalized === "ingress") return tr(locale, "Ingress", "入口");
  if (normalized === "egress") return tr(locale, "Egress", "出口");
  if (normalized === "output") return tr(locale, "Output", "输出");
  return pipeline || tr(locale, "unknown", "未知");
}

export function agentStatusLabel(locale: Locale, state: "protected" | "needs_attention" | "available" | "missing"): string {
  if (state === "needs_attention") return tr(locale, "Needs attention", "保护需修复");
  if (state === "protected") return tr(locale, "Protected", "已保护");
  if (state === "available") return tr(locale, "Available", "可用");
  return tr(locale, "Not found", "未发现");
}

export function portStatusLabel(locale: Locale, port?: PortStatus, fallbackPort?: number): string {
  const value = port?.port ?? fallbackPort;
  if (!value) return statusWord(locale, "unknown");
  const state = port?.status ? ` ${statusWord(locale, port.status)}` : "";
  return `${value}${state}`;
}

export function slmStatusLabel(locale: Locale, value?: string | null): string {
  return statusWord(locale, value || "unavailable");
}
