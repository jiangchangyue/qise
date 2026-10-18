import { useEffect, useRef, useState } from "react";
import { agentAction, agentStatus, type AgentInfo } from "../lib/api";
import { agentStatusLabel, tr, type Locale } from "../lib/locale";
import "./data-panels.css";

interface AgentTaskState {
  status: "idle" | "running" | "succeeded" | "failed";
  action?: string;
  error?: string;
}

interface AgentPanelProps {
  agents: AgentInfo[];
  task: AgentTaskState;
  onProtect: (agent: AgentInfo, baseUrl: string) => void;
  onRestore: (agent: AgentInfo) => void;
  locale: Locale;
}

const PAGE_SIZE = 5;

function coverageLabel(locale: Locale, coverage: string): string {
  const labels: Record<string, [string, string]> = {
    preflight: ["Preflight safety checks", "运行前安全体检"],
    model_traffic: ["Connected model traffic", "模型通信检查"],
    manual_connection: ["Manual model connection", "手动模型接入"],
    runtime_observation: ["Runtime observation · start separately", "运行观察 · 需单独启动"],
  };
  const label = labels[coverage];
  return label ? tr(locale, ...label) : coverage;
}

export default function AgentPanel({ agents, task, onProtect, onRestore, locale }: AgentPanelProps) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [confirmAgent, setConfirmAgent] = useState<AgentInfo | null>(null);
  const [confirmBaseUrl, setConfirmBaseUrl] = useState("");
  const confirmDialog = useRef<HTMLDialogElement>(null);
  const anyBusy = task.status === "running";
  const busyAgent = anyBusy && task.action?.includes(":") ? task.action.split(":")[1] : null;
  const filtered = agents.filter((agent) => `${agent.name} ${agent.key}`.toLowerCase().includes(query.toLowerCase()));
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleAgents = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const selected = visibleAgents.find((agent) => agent.key === selectedKey) || visibleAgents[0];

  useEffect(() => {
    if (confirmAgent && confirmDialog.current && !confirmDialog.current.open) confirmDialog.current.showModal();
  }, [confirmAgent]);

  function closeConfirmation() {
    confirmDialog.current?.close();
    setConfirmAgent(null);
    setConfirmBaseUrl("");
  }

  return (
    <section className="qise-card agent-panel">
      <div className="agent-toolbar">
        <div><strong>{tr(locale, "Your applications", "本机应用")}</strong><span className="agent-count">{agents.length}</span></div>
        <input className="qise-input agent-search" aria-label={tr(locale, "Find application", "搜索应用")}
          placeholder={tr(locale, "Find application…", "搜索应用…")} value={query}
          onChange={(event) => { setQuery(event.target.value); setPage(0); }} />
      </div>
      {task.status === "failed" && task.error && <p role="alert" className="agent-error">{task.error}</p>}
      <div className="agent-workspace">
        <div className="agent-list" aria-label={tr(locale, "Applications", "应用列表")}>
          {visibleAgents.map((agent) => (
            <button key={agent.key} className={`agent-list-row ${selected?.key === agent.key ? "is-selected" : ""}`}
              aria-pressed={selected?.key === agent.key} onClick={() => setSelectedKey(agent.key)}>
              <span className="agent-monogram" aria-hidden="true">{agent.name.slice(0, 1).toUpperCase()}</span>
              <span className="agent-list-copy"><strong>{agent.name}</strong><small>{agent.experimental ? tr(locale, "Experimental integration", "实验性接入") : tr(locale, "Local application", "本机应用")}</small></span>
              <span className={`agent-state agent-state-${agentStatus(agent)}`}><i />{agentStatusLabel(locale, agentStatus(agent))}</span>
              <span className="agent-row-arrow" aria-hidden="true">›</span>
            </button>
          ))}
          {visibleAgents.length === 0 && <div className="agent-empty">{tr(locale, "No applications found.", "未找到应用。")}</div>}
        </div>
        {selected && <aside className="agent-detail" aria-label={tr(locale, "Application details", "应用详情")}>
          <div className="agent-detail-heading"><span className="agent-detail-kicker">{tr(locale, "APPLICATION", "应用详情")}</span><h3>{selected.name}</h3></div>
          <div className="agent-detail-content">
            {selected.protection_status === "needs_attention" && <p className="agent-notice">{tr(locale, "Protection is not active. Restore the original settings before reconnecting.", "保护当前未生效。请先恢复原设置，再重新开启保护。")}</p>}
            {agentAction(selected) === "manual" && <p className="agent-notice">{tr(locale, "Manual connection required. Open Custom connection to configure this application; automatic protection is unavailable.", "需手动接入：请打开「自定义接入」完成配置，暂不支持自动保护。")}</p>}
            <dl className="agent-metadata"><dt>{tr(locale, "Configuration", "配置位置")}</dt><dd>{selected.config_path || selected.cli_path || tr(locale, "No local configuration detected", "未检测到本地配置")}</dd></dl>
            {!!selected.coverage?.length && <div className="agent-coverage"><h4>{tr(locale, "Protection coverage", "保护范围")}</h4>{selected.coverage.map((detail) => <p key={detail}><span aria-hidden="true">—</span>{coverageLabel(locale, detail)}</p>)}</div>}
            {selected.note && <p className="agent-note">{selected.note}</p>}
          </div>
          <div className="agent-detail-actions">
            {agentAction(selected) === "restore" ? <button className="qise-action qise-action-secondary" disabled={anyBusy} onClick={() => onRestore(selected)}>
              {busyAgent === selected.key ? tr(locale, "Restoring…", "正在恢复…") : tr(locale, "Restore", "恢复")}
            </button> : agentAction(selected) === "protect" ? <button className="qise-action qise-action-primary" disabled={anyBusy} onClick={() => { setConfirmAgent(selected); setConfirmBaseUrl(selected.key === "claude-code" ? "https://api.anthropic.com" : ""); }}>
              {busyAgent === selected.key ? tr(locale, "Protecting…", "正在保护…") : tr(locale, "Protect", "保护")}
            </button> : <span className="agent-action-hint">{agentAction(selected) === "manual" ? tr(locale, "Custom connection", "通过自定义接入配置") : tr(locale, "Install this application to connect", "安装应用后即可接入")}</span>}
          </div>
        </aside>}
      </div>
      <footer className="agent-pagination"><span>{tr(locale, `${filtered.length} applications`, `共 ${filtered.length} 个应用`)}</span><div><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} aria-label={tr(locale, "Previous page", "上一页")}>‹</button><span>{currentPage + 1} / {pageCount}</span><button disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)} aria-label={tr(locale, "Next page", "下一页")}>›</button></div></footer>
      {confirmAgent && <dialog ref={confirmDialog} className="agent-dialog" onCancel={closeConfirmation} aria-labelledby="agent-confirm-title">
        <div className="agent-dialog-header"><div><span className="agent-detail-kicker">{tr(locale, "CONNECT APPLICATION", "应用接入")}</span><h3 id="agent-confirm-title">{tr(locale, "Protect", "保护")} {confirmAgent.name}</h3></div><button className="agent-close" aria-label={tr(locale, "Close", "关闭")} onClick={closeConfirmation}>×</button></div>
        <div className="agent-dialog-content">
          <label className="agent-field">{tr(locale, "Upstream model API URL", "上游模型 API 地址")}<input className="qise-input" value={confirmBaseUrl} onChange={(event) => setConfirmBaseUrl(event.target.value)} placeholder={confirmAgent.key === "claude-code" ? "https://api.anthropic.com" : "https://api.openai.com/v1"} /></label>
          <p className="agent-note">{confirmAgent.key === "claude-code" ? tr(locale, "Claude Code uses Anthropic Messages traffic. Keep ANTHROPIC_API_KEY available and use the Anthropic upstream above.", "Claude Code 使用 Anthropic Messages 流量。请保持 ANTHROPIC_API_KEY 可用，并使用上方 Anthropic 上游地址。") : tr(locale, "Leave this empty if Qise can infer the upstream from the application configuration.", "如果 Qise 可以从应用配置推断上游地址，可以留空。")}</p>
          <dl className="agent-confirm-metadata"><dt>{tr(locale, "Configuration", "配置")}</dt><dd>{confirmAgent.config_path || tr(locale, "Not detected", "未检测到")}</dd><dt>{tr(locale, "Backup", "备份")}</dt><dd>{`~/.qise/backups/${confirmAgent.key}/<timestamp>/`}</dd><dt>{tr(locale, "Command", "命令")}</dt><dd>qise protect {confirmAgent.key}{confirmBaseUrl.trim() ? ` --base-url ${confirmBaseUrl.trim()}` : ""}</dd></dl>
          <p className="agent-notice">{tr(locale, "Qise will update the configuration after confirming the upstream address.", "Qise 会在确认上游地址后再修改应用配置。")}</p>
        </div>
        <div className="agent-dialog-actions"><button className="qise-action qise-action-secondary" onClick={closeConfirmation}>{tr(locale, "Cancel", "取消")}</button><button className="qise-action qise-action-primary" disabled={anyBusy} onClick={() => { onProtect(confirmAgent, confirmBaseUrl.trim()); closeConfirmation(); }}>{tr(locale, "Confirm", "确认")}</button></div>
      </dialog>}
    </section>
  );
}
