import Icon from "./Icon";
import { type PageId } from "./DesktopShell";
import { type AgentInfo, type AppStatus, type GuardInfo, statusProtectionEnabled, statusHasConfiguredAgents, statusEventCounts, slmTone } from "../lib/api";
import { tr, type Locale } from "../lib/locale";
export interface HomePageProps {
  status: AppStatus | null; guards: GuardInfo[]; agents: AgentInfo[]; locale: Locale;
  onOpen: (page: PageId) => void; onDetectAgents: () => void; onQuickScan: () => void;
  detectingAgents: boolean; scanning: boolean;
}
export default function HomeOverview({ status, guards, agents, onOpen, locale }: HomePageProps) {
  const protectedNow = statusProtectionEnabled(status);
  const attention = statusHasConfiguredAgents(status) && !protectedNow;
  const connected = agents.filter(a => a.protected).length;
  const installed = agents.filter(a => a.installed || a.configured);
  const counts = statusEventCounts(status);
  const title = !status ? tr(locale, "Checking protection status", "保护状态待确认")
    : protectedNow ? tr(locale, "Your agents are protected", "智能保护已开启")
    : attention ? tr(locale, "A connection needs attention", "保护需要修复")
    : status.services_running ? tr(locale, "Ready to connect", "服务已就绪，等待接入")
    : tr(locale, "Ready when you are", "智能保护未开启");
  const detail = !status ? tr(locale, "Checking the local runtime. Please wait.", "正在确认本地运行状态，请稍候。")
    : protectedNow ? slmTone(status) === "ready" ? tr(locale, "Local rules and model review are working together.", "本地规则与模型审查正在协同保护。") : tr(locale, "Protected by local rules. Model review is optional.", "当前使用本地规则保护，增强检测可按需开启。")
    : attention ? tr(locale, "Restore the original settings or reconnect your agent.", "恢复原设置或重新接入，让保护重新生效。")
    : status.services_running ? tr(locale, "Connect an agent. Manual routes need your own verification.", "连接智能体以启用保护；手动接入需自行检查路由。")
    : tr(locale, "Services are stopped. Start with a safety check.", "保护服务已停止，建议先进行一次安全体检。");
  const items = [
    { id: "events" as const, icon: "events" as const, title: tr(locale, "Security events", "安全事件"), detail: tr(locale, "Review decisions & evidence", "查看拦截记录与判定证据") },
    { id: "rules" as const, icon: "rules" as const, title: tr(locale, "Protection rules", "防护规则"), detail: guards.length ? tr(locale, `${guards.length} guards available`, `${guards.length} 个守卫，按需配置`) : tr(locale, "Review your guard policies", "查看守卫与处置策略") },
    { id: "backup" as const, icon: "backup" as const, title: tr(locale, "Backup & restore", "备份恢复"), detail: tr(locale, "Restore original settings", "管理与恢复原始配置") },
    { id: "slm" as const, icon: "model" as const, title: tr(locale, "Enhanced detection", "增强检测"), detail: tr(locale, "Configure model review", "管理本地与远程模型审查") },
  ];
  return <div className="overview-workspace">
    <section className={`protection-console ${protectedNow ? "is-protected" : ""}`} aria-label={tr(locale, "Protection status", "保护状态")}>
      <div className="overview-health">
        <div className="health-art" aria-hidden="true"><div className="health-orbit health-orbit-outer" /><div className="health-orbit health-orbit-inner" /><div className="health-shield"><svg width="89" height="104" viewBox="0 0 120 140" fill="none"><defs><linearGradient id="shield-metal" x1="17" y1="15" x2="104" y2="126" gradientUnits="userSpaceOnUse"><stop stopColor="#f2f5fb" /><stop offset=".48" stopColor="#c7d4e8" /><stop offset="1" stopColor="#7c93b5" /></linearGradient><linearGradient id="shield-face" x1="35" y1="22" x2="89" y2="115" gradientUnits="userSpaceOnUse"><stop stopColor="#6b82a6" /><stop offset="1" stopColor="#354c6e" /></linearGradient></defs><path d="M60 5 107 25v37c0 32-21 56-47 70C34 118 13 94 13 62V25L60 5Z" fill="url(#shield-metal)" stroke="#d8e3f3" strokeWidth=".8" /><path d="m60 14 39 17v31c0 27-17 48-39 61-22-13-39-34-39-61V31l39-17Z" fill="url(#shield-face)" stroke="#94a9c8" strokeWidth="1" /><path d="m60 15 38 17v30c0 27-17 48-38 60V15Z" fill="#233d611c" /><path d={protectedNow ? "m39 66 15 15 29-34" : "M60 44v28m0 14v2"} stroke="#edf3fc" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" /></svg></div><span className="health-art-indicator"><Icon name={protectedNow ? "check" : "help"} size={15} /></span></div>
        <div className="health-copy"><span className="eyebrow">QISE · {tr(locale, "PROTECTION CENTER", "安全防护中心")}</span><h2>{title}</h2><p>{detail}</p><div className="health-actions"><button className="health-primary-action" data-page="preflight" onClick={() => onOpen("preflight")}><Icon name="scan" size={18} />{tr(locale, "Start a safety check", "一键安全体检")}<Icon name="arrow" size={16} /></button><button className="health-secondary-action" data-page="shield" onClick={() => onOpen("shield")}>{tr(locale, "Manage protection", "管理保护")}<Icon name="chevron" size={14} /></button></div></div>
        <div className="health-metrics"><span className="health-metrics-label">{tr(locale, "LAST 24 HOURS", "过去 24 小时")}</span><div className="health-metric-numbers"><button data-page="events" onClick={() => onOpen("events")}><strong>{status ? counts.blocked : "—"}</strong><span>{tr(locale, "Blocked", "风险拦截")}</span></button><button data-page="events" onClick={() => onOpen("events")}><strong>{status ? counts.warnings : "—"}</strong><span>{tr(locale, "Warnings", "安全提醒")}</span></button></div><button className="health-events-link" data-page="events" onClick={() => onOpen("events")}>{tr(locale, "Security events", "查看安全事件")}<Icon name="arrow" size={14} /></button></div>
      </div>
      <div className="protection-status-strip">
        <button onClick={() => onOpen("shield")}><Icon name="shield" size={17} /><span>{tr(locale, "Agent protection", "智能体保护")}</span><strong>{status ? tr(locale, `${connected} connected`, `${connected} 个已保护`) : tr(locale, "Checking", "待确认")}</strong><Icon name="chevron" size={13} /></button>
        <button onClick={() => onOpen("rules")}><Icon name="rules" size={17} /><span>{tr(locale, "Local rules", "本地规则")}</span><strong>{guards.length ? tr(locale, `${guards.filter(g => g.mode !== "off").length} enabled`, `${guards.filter(g => g.mode !== "off").length} 个已启用`) : "—"}</strong><Icon name="chevron" size={13} /></button>
        <button onClick={() => onOpen("slm")}><Icon name="model" size={17} /><span>{tr(locale, "Model review", "模型审查")}</span><strong>{slmTone(status) === "ready" ? tr(locale, "Ready", "已就绪") : tr(locale, "View status", "查看状态")}</strong><Icon name="chevron" size={13} /></button>
      </div>
    </section>
    <div className="overview-lower">
      <section className="overview-agent-panel"><header className="overview-panel-heading"><h2>{tr(locale, "Your agents", "我的智能体")}<span>{installed.length}</span></h2><button onClick={() => onOpen("shield")}>{tr(locale, "Manage all", "管理全部")}<Icon name="chevron" size={13} /></button></header><div className="overview-agent-list">{installed.slice(0, 4).map(agent => <button key={agent.key} className="overview-agent-row" onClick={() => onOpen("shield")}><span className={`overview-agent-monogram agent-mark-${agent.key}`}>{agent.name.slice(0, 1)}</span><span className="overview-agent-name"><strong>{agent.name}</strong><small>{agent.experimental ? tr(locale, "Experimental integration", "实验性接入") : tr(locale, "Local application", "本地应用")}</small></span><span className={`overview-agent-state ${agent.protected ? "is-on" : agent.configured ? "needs-attention" : ""}`}><i />{agent.protected ? tr(locale, "Protected", "保护中") : agent.configured ? tr(locale, "Needs attention", "待修复") : tr(locale, "Not connected", "未接入")}</span><Icon name="chevron" size={13} /></button>)}{installed.length === 0 && <div className="overview-agents-empty"><Icon name="shield" size={25} /><p>{tr(locale, "Connect your first agent to start protecting your workflow.", "接入你的第一个智能体，开始保护工作流。")}</p><button className="qise-action qise-action-secondary" onClick={() => onOpen("shield")}>{tr(locale, "Manage agents", "管理智能体")}</button></div>}</div></section>
      <section className="overview-shortcuts"><header className="overview-panel-heading"><h2>{tr(locale, "Quick access", "快捷工作区")}</h2><button onClick={() => onOpen("tools")}>{tr(locale, "Toolbox", "工具箱")}<Icon name="chevron" size={13} /></button></header><div className="overview-actions">{items.map(item => <button className="overview-action-card" key={item.id} data-page={item.id} onClick={() => onOpen(item.id)}><span className={`action-icon action-icon-${item.id}`}><Icon name={item.icon} size={23} /></span><span className="action-card-copy"><h3>{item.title}</h3><p>{item.detail}</p></span><Icon name="chevron" size={14} /></button>)}</div><div className="overview-shortcut-note"><Icon name="lock" size={14} />{tr(locale, "Local-first. Your settings stay in your control.", "本地优先，配置与工作流始终由你掌控。")}</div></section>
    </div>
    <div className="overview-footnote"><span>{tr(locale, "Protection applies to connected agents and enabled rules.", "保护范围取决于已接入的智能体与启用的规则。")}</span><button onClick={() => onOpen("doctor")}><Icon name="activity" size={14} />{tr(locale, "System diagnostics", "系统诊断")}<Icon name="chevron" size={13} /></button></div>
  </div>;
}
