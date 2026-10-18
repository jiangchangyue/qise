import type { ReactNode } from "react";
import Icon, { type IconName } from "./Icon";
import { statusProtectionEnabled, type AppStatus } from "../lib/api";
import { tr, type Locale } from "../lib/locale";
export type PageId = "home" | "shield" | "preflight" | "events" | "rules" | "slm" | "doctor" | "observer" | "backup" | "integrations" | "advanced" | "settings" | "tools";
export const PAGE_META: Record<PageId, { en: string; zh: string; icon: IconName; description: [string, string] }> = {
  home: { en: "Overview", zh: "安全总览", icon: "home", description: ["Your agents. Your control.", "保护状态与常用功能，尽在这里。"] },
  shield: { en: "Agents", zh: "智能体保护", icon: "shield", description: ["Manage connections and protection.", "管理智能体接入，确认每一条保护连接。"] },
  preflight: { en: "Safety check", zh: "安全体检", icon: "scan", description: ["Review risks before you connect.", "在接入前，检查配置、技能与 MCP 风险。"] },
  events: { en: "Security events", zh: "安全事件", icon: "events", description: ["Every decision, with the evidence behind it.", "查看风险判定、拦截记录与相关证据。"] },
  rules: { en: "Protection rules", zh: "防护规则", icon: "rules", description: ["Set the boundaries for your agents.", "为智能体的输入、操作与输出设定边界。"] },
  slm: { en: "Enhanced detection", zh: "增强检测", icon: "model", description: ["Optional model review, on your terms.", "按需添加模型审查，基础防护无需模型。"] },
  doctor: { en: "Diagnostics", zh: "系统诊断", icon: "activity", description: ["Check your runtime and connections.", "检查运行环境、服务与配置状态。"] },
  observer: { en: "Runtime observer", zh: "运行观察", icon: "activity", description: ["Inspect agent activity in a session.", "创建观察命令，查看会话中的实际行为。"] },
  backup: { en: "Backups", zh: "备份恢复", icon: "backup", description: ["Original settings, always recoverable.", "查看原始配置备份，按需恢复接入前的设置。"] },
  integrations: { en: "Integrations", zh: "开发者集成", icon: "code", description: ["Bring Qise into your workflow.", "通过 SDK、MCP 或代理接入你的工作流。"] },
  advanced: { en: "Rule lab", zh: "规则实验室", icon: "flask", description: ["Inspect rules with a sample tool call.", "使用工具调用样例检查判定与安全上下文。"] },
  settings: { en: "Settings", zh: "偏好设置", icon: "settings", description: ["Configure Qise for your workspace.", "管理应用、模型、连接与守卫参数。"] },
  tools: { en: "Toolbox", zh: "工具箱", icon: "tools", description: ["Everything else, within reach.", "诊断、观察与集成，为进阶工作流准备。"] },
};
const main: PageId[] = ["home", "shield", "preflight", "events", "rules"];
const extra: PageId[] = ["slm", "backup", "tools"];
export default function DesktopShell({ page, onOpen, locale, onToggleLocale, status, version, children, actions, notices }: {
  page: PageId; onOpen: (page: PageId) => void; locale: Locale; onToggleLocale: () => void;
  status: AppStatus | null; version: string; children: ReactNode; actions?: ReactNode; notices?: ReactNode;
}) {
  const protectedNow = statusProtectionEnabled(status);
  const meta = PAGE_META[page];
  function nav(item: PageId) {
    const selected = item === page || item === "tools" && ["doctor", "observer", "integrations", "advanced"].includes(page);
    return <button key={item} className={`desktop-nav-item ${selected ? "is-active" : ""}`} data-page={item} title={PAGE_META[item][locale]} aria-current={selected ? "page" : undefined} onClick={() => onOpen(item)}><Icon name={PAGE_META[item].icon} /><span>{item === "slm" && locale === "en" ? "Detection" : PAGE_META[item][locale]}</span>{item === "events" && (status?.events_24h?.blocked ?? 0) > 0 && <span className="nav-count">{status?.events_24h?.blocked}</span>}</button>;
  }
  return <div className="desktop-app">
    <header className="desktop-titlebar">
      <button className="desktop-brand" onClick={() => onOpen("home")} aria-label="Qise"><span className="brand-mark"><Icon name="shield" size={23} /></span><strong>Qise</strong><span className="brand-caption">{tr(locale, "AGENT SECURITY", "智能体安全防护")}</span></button>
      <div className="titlebar-right">
        {__QISE_BROWSER_PREVIEW__ && <span className="preview-label" role="note" title={tr(locale, "Sample data. No backend connected.", "全部为示例数据，未连接后端。")}>{tr(locale, "UI preview · sample data", "UI 预览 · 示例数据")}</span>}
        <button className="titlebar-button" onClick={onToggleLocale} aria-label={tr(locale, "Switch language", "切换语言")}><Icon name="globe" size={15} />{locale === "zh" ? "EN" : "中文"}</button>
        <button className={`titlebar-button ${page === "settings" ? "is-active" : ""}`} data-page="settings" aria-current={page === "settings" ? "page" : undefined} onClick={() => onOpen("settings")}><Icon name="settings" size={16} /><span>{tr(locale, "Settings", "设置")}</span></button>
      </div>
    </header>
    <nav className="desktop-navigation" aria-label={tr(locale, "Main navigation", "主导航")}><div className="desktop-nav-inner"><div className="nav-primary">{main.map(nav)}</div><div className="nav-secondary">{extra.map(nav)}</div></div></nav>
    <div className="desktop-main">
      <div className="desktop-content">
        <div className="desktop-page-heading"><div className="page-heading-copy"><h1>{meta[locale]}</h1><p>{tr(locale, ...meta.description)}</p></div><div className="page-heading-actions">{actions}</div></div>
        {notices}
        <main className="desktop-page" data-active-page={page} key={page}>{children}</main>
      </div>
      <footer className="desktop-statusbar"><span><i className={`status-dot ${protectedNow ? "is-on" : "is-off"}`} />{protectedNow ? tr(locale, "Protection active", "保护运行中") : status ? tr(locale, "Protection inactive", "保护未开启") : tr(locale, "Checking status", "正在确认状态")}</span><span><Icon name="lock" size={11} />{tr(locale, "Local workspace", "本地工作空间")}<span className="statusbar-version">{version ? `v${version}` : "—"}</span></span></footer>
    </div>
  </div>;
}
export function ToolsPage({ onOpen, locale }: { onOpen: (page: PageId) => void; locale: Locale }) {
  return <div className="toolbox-grid">{(["doctor", "observer", "integrations", "advanced"] as PageId[]).map(id => <button className="toolbox-card" data-page={id} key={id} onClick={() => onOpen(id)}><Icon name={PAGE_META[id].icon} size={24} /><h2>{PAGE_META[id][locale]}</h2><p>{tr(locale, ...PAGE_META[id].description)}</p><span>{tr(locale, "Open", "打开")}<Icon name="arrow" size={16} /></span></button>)}</div>;
}
