import { useState } from "react";
import { agentAction, agentStatus, type AgentInfo } from "../lib/api";
import { agentStatusLabel, tr, type Locale } from "../lib/locale";

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

function statusColor(agent: AgentInfo): string {
  if (agent.protected) return "var(--qise-green)";
  if (agent.installed || agent.configured) return "var(--qise-yellow)";
  return "var(--indicator-muted)";
}

function backupPreview(agent: AgentInfo): string {
  return `~/.qise/backups/${agent.key}/<timestamp>/`;
}

function suggestedBaseUrl(agent: AgentInfo): string {
  if (agent.key === "claude-code") return "https://api.anthropic.com";
  return "";
}

function baseUrlPlaceholder(agent: AgentInfo): string {
  if (agent.key === "claude-code") return "https://api.anthropic.com";
  return "https://api.openai.com/v1";
}

export default function AgentPanel({ agents, task, onProtect, onRestore, locale }: AgentPanelProps) {
  const [confirmAgent, setConfirmAgent] = useState<AgentInfo | null>(null);
  const [confirmBaseUrl, setConfirmBaseUrl] = useState("");
  const anyBusy = task.status === "running";
  const busyAgent = task.status === "running" && task.action?.includes(":")
    ? task.action.split(":")[1]
    : null;

  return (
    <div className="qise-card p-4">
      {task.status === "failed" && task.error && (
        <div className="mb-3 rounded-lg border border-[rgba(255,95,111,0.35)] bg-[rgba(255,95,111,0.08)] px-3 py-2">
          <p className="text-xs text-qise-red">{task.error}</p>
        </div>
      )}

      {agents.map((agent) => (
        <div
          key={agent.key}
          className="flex items-center justify-between gap-3 py-3 px-3 rounded-lg hover:bg-[var(--bg-card)]"
        >
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-2 h-2 rounded-full shrink-0"
              style={{
                backgroundColor: statusColor(agent),
                boxShadow: agent.protected ? `0 0 8px ${statusColor(agent)}` : undefined,
              }}
            />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm text-[var(--text-primary)]">{agent.name}</span>
                {agent.experimental && (
                  <span className="text-[10px] text-[var(--text-dim)]">
                    {tr(locale, "experimental", "实验性")}
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-dim)] truncate">
                {agent.config_path || agent.cli_path || agent.note || tr(locale, "No local config detected", "未检测到本地配置")}
              </p>
              {agent.protection_status === "needs_attention" && (
                <p className="mt-1 text-xs text-qise-yellow">
                  {tr(locale, "Protection is not active. Restore the original settings before reconnecting.", "保护当前未生效。可先恢复原设置，再重新开启保护。")}
                </p>
              )}
              {agent.coverage?.map((detail) => (
                <p key={detail} className="mt-1 text-xs text-[var(--text-dim)]">{
                  detail === "preflight" ? tr(locale, "Preflight safety checks", "支持运行前安全体检")
                    : detail === "model_traffic" ? tr(locale, "Checks connected model traffic", "检查接入后的模型通信")
                      : detail === "manual_connection" ? tr(locale, "Connect in your model settings", "需在模型设置中手动接入")
                        : detail === "runtime_observation" ? tr(locale, "Runtime observation requires a separate start", "运行观察需单独启动")
                          : detail
                }</p>
              ))}
            </div>
            <span
              className="text-xs px-2 py-0.5 rounded-full shrink-0"
              style={{
                color: statusColor(agent),
                backgroundColor: `${statusColor(agent)}20`,
              }}
            >
              {agentStatusLabel(locale, agentStatus(agent))}
            </span>
          </div>

          {agentAction(agent) !== "unavailable" && (
            agentAction(agent) === "restore" ? (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-[var(--button-primary-bg)] text-[var(--button-primary-text)] hover:opacity-60 transition-opacity disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => onRestore(agent)}
              >
                {busyAgent === agent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner" />{tr(locale, "Restoring...", "正在恢复...")}</span>
                ) : tr(locale, "Restore", "恢复")}
              </button>
            ) : agentAction(agent) === "manual" ? (
              <p className="max-w-48 text-xs text-[var(--text-tertiary)]">
                {tr(locale, "Manual connection required. Use the custom connection settings below; automatic protection is unavailable.", "需手动接入：请使用下方自定义接入设置，暂不支持自动保护。")}
              </p>
            ) : (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-transparent border border-[var(--border-strong)] text-[var(--text-primary)] hover:opacity-60 transition-opacity disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => {
                  setConfirmAgent(agent);
                  setConfirmBaseUrl(suggestedBaseUrl(agent));
                }}
              >
                {busyAgent === agent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner qise-spinner-blue" />{tr(locale, "Protecting...", "正在保护...")}</span>
                ) : tr(locale, "Protect", "保护")}
              </button>
            )
          )}
        </div>
      ))}

      {agents.length === 0 && (
        <p className="text-sm text-[var(--text-dim)] text-center py-4">
          {tr(locale, "No agents detected.", "未检测到智能体。")}
        </p>
      )}

      {confirmAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(35,68,96,0.28)] px-4">
          <div className="w-full max-w-lg rounded-lg border border-[var(--border-subtle)] bg-qise-surface p-5 shadow-double-ring">
            <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">
              {tr(locale, "Protect", "保护")} {confirmAgent.name}
            </h3>
            <div className="space-y-2 text-xs text-[var(--text-tertiary)]">
              <p>
                {tr(locale, "Command", "命令")}：<span className="break-all font-mono text-[var(--text-secondary)]">qise protect {confirmAgent.key}{confirmBaseUrl.trim() ? ` --base-url ${confirmBaseUrl.trim()}` : ""}</span>
              </p>
              <p>
                {tr(locale, "Config", "配置")}：<span className="break-all font-mono text-[var(--text-secondary)]">{confirmAgent.config_path || tr(locale, "not detected", "未检测到")}</span>
              </p>
              <p>
                {tr(locale, "Backup", "备份")}：<span className="break-all font-mono text-[var(--text-secondary)]">{backupPreview(confirmAgent)}</span>
              </p>
              <label className="block">
                <span className="text-xs text-[var(--text-tertiary)]">
                  {tr(locale, "Upstream model API URL", "上游模型 API 地址")}
                </span>
                <input
                  className="qise-input mt-1"
                  value={confirmBaseUrl}
                  onChange={(event) => setConfirmBaseUrl(event.target.value)}
                  placeholder={baseUrlPlaceholder(confirmAgent)}
                />
              </label>
              <p>
                {confirmAgent.key === "claude-code"
                  ? tr(locale, "Claude Code uses Anthropic Messages traffic. Keep ANTHROPIC_API_KEY available, then use the Anthropic upstream above.", "Claude Code 使用 Anthropic Messages 流量。请保持 ANTHROPIC_API_KEY 可用，并使用上方 Anthropic 上游地址。")
                  : tr(locale, "Leave this empty if Qise can infer the upstream from the agent config.", "如果 Qise 可以从智能体配置推断上游地址，可以留空。")}
              </p>
              <p className="text-qise-yellow">
                {tr(locale, "Qise will patch the Agent config only after the product CLI confirms an upstream.", "Qise 会在命令行确认上游地址后再修改智能体配置。")}
              </p>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                className="px-4 py-2 rounded-[43px] text-sm font-medium bg-[var(--bg-card)] text-[var(--text-tertiary)] hover:opacity-60 transition-all"
                onClick={() => {
                  setConfirmAgent(null);
                  setConfirmBaseUrl("");
                }}
              >
                {tr(locale, "Cancel", "取消")}
              </button>
              <button
                className="px-4 py-2 rounded-[43px] text-sm font-medium bg-[var(--button-primary-bg)] text-[var(--button-primary-text)] hover:opacity-60 transition-all disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => {
                  onProtect(confirmAgent, confirmBaseUrl.trim());
                  setConfirmAgent(null);
                  setConfirmBaseUrl("");
                }}
              >
                {busyAgent === confirmAgent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner" />{tr(locale, "Protecting...", "正在保护...")}</span>
                ) : tr(locale, "Confirm", "确认")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
