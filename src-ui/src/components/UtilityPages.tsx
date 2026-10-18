import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AppStatus, SecurityEvent } from "../lib/api";
import { pipelineLabel, tr, verdictLabel, type Locale } from "../lib/locale";
import Icon from "./Icon";
import "./utility-pages.css";

type ErrorSetter = (error: string | null) => void;
type Pipeline = "ingress" | "egress" | "output";
const ADAPTERS = ["nanobot", "hermes", "nexau", "langgraph", "openai-agents"] as const;
const RUNTIME_COMMANDS = [
  { name: "OpenAI proxy", zh: "OpenAI 代理", command: "qise proxy start --upstream https://api.openai.com/v1" },
  { name: "Anthropic proxy", zh: "Anthropic 代理", command: "qise proxy start --upstream https://api.anthropic.com" },
  { name: "Bridge", zh: "桥接服务", command: "qise bridge start" },
  { name: "MCP stdio", zh: "MCP 标准输入输出", command: "qise serve --transport stdio" },
];

function PanelHeader({ title, detail, children }: { title: string; detail?: string; children?: ReactNode }) {
  return <header className="utility-panel-header"><div><h3>{title}</h3>{detail && <p>{detail}</p>}</div>{children}</header>;
}

function Pagination({ page, total, onPage, locale }: { page: number; total: number; onPage: (page: number) => void; locale: Locale }) {
  return <div className="utility-pagination"><button disabled={page === 0} onClick={() => onPage(page - 1)} aria-label={tr(locale, "Previous page", "上一页")}><Icon name="chevron" size={14} className="utility-previous" /></button><span>{page + 1} / {total}</span><button disabled={page + 1 >= total} onClick={() => onPage(page + 1)} aria-label={tr(locale, "Next page", "下一页")}><Icon name="chevron" size={14} /></button></div>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="utility-empty"><Icon name="activity" size={26} /><strong>{title}</strong><p>{detail}</p></div>;
}

export function BackupRestorePage({ status, onRefresh, setError, locale }: { status: AppStatus | null; onRefresh: () => Promise<void>; setError: ErrorSetter; locale: Locale }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [output, setOutput] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [page, setPage] = useState(0);
  const records = Object.entries(status?.protected_agents ?? {});
  const totalPages = Math.max(1, Math.ceil(records.length / 4));
  const currentPage = Math.min(page, totalPages - 1);
  const visibleRecords = records.slice(currentPage * 4, currentPage * 4 + 4);
  const selected = records.find(([key]) => key === selectedKey) ?? visibleRecords[0];

  async function restoreAgent(agent: string) {
    setBusy(agent); setError(null);
    try { await invoke("restore_agent", { agent }); setOutput(tr(locale, `Restored ${agent}.`, `已恢复 ${agent}。`)); await onRefresh(); }
    catch (error) { setError(String(error)); }
    finally { setBusy(null); }
  }
  async function restoreAll() {
    if (!window.confirm(tr(locale, "Restore all agent configs modified by Qise?", "恢复所有被 Qise 修改过的智能体配置？"))) return;
    setBusy("all"); setError(null);
    try {
      const result = await invoke<{ stdout: string; stderr: string; success: boolean; exit_status: string }>("restore_all_agents");
      const text = result.stdout || result.stderr || tr(locale, `Command exited with ${result.exit_status}.`, `命令退出状态：${result.exit_status}。`);
      if (!result.success) throw new Error(text);
      setOutput(text); await onRefresh();
    } catch (error) { setError(String(error)); }
    finally { setBusy(null); }
  }
  return <div className="utility-layout utility-backup-layout">
    <section className="qise-card utility-panel">
      <PanelHeader title={tr(locale, "Configuration backups", "配置备份")} detail={tr(locale, "Original settings saved before protection.", "启用保护前保存的原始设置。") }><span className="utility-count">{records.length}</span></PanelHeader>
      <div className="utility-list">
        {visibleRecords.map(([key, record]) => <button key={key} className={`utility-backup-row ${selected?.[0] === key ? "is-selected" : ""}`} onClick={() => setSelectedKey(key)} aria-pressed={selected?.[0] === key}>
          <span className="utility-row-icon"><Icon name="backup" size={20} /></span><span className="utility-row-text"><strong>{record.display_name || record.agent || key}</strong><small>{record.protected_at ? record.protected_at.replace("T", " ").slice(0, 16) : tr(locale, "Original configuration", "原始配置")}</small></span><span className="utility-ready"><i />{tr(locale, "Ready", "可恢复")}</span><Icon name="chevron" size={14} />
        </button>)}
        {!records.length && <EmptyState title={tr(locale, "No backups yet", "暂无配置备份")} detail={tr(locale, "Protect an agent to save its original settings here.", "保护智能体后，原始配置会保存在这里。") } />}
      </div>
      <footer className="utility-panel-footer"><button className="qise-action qise-action-secondary" disabled={busy !== null || !records.length} onClick={restoreAll}>{busy === "all" ? tr(locale, "Restoring…", "正在恢复…") : tr(locale, "Restore all", "全部恢复")}</button><Pagination page={currentPage} total={totalPages} onPage={(next) => { setPage(next); setSelectedKey(""); }} locale={locale} /></footer>
    </section>
    <section className="qise-card utility-panel">
      <PanelHeader title={selected ? selected[1].display_name || selected[1].agent || selected[0] : tr(locale, "Backup details", "备份详情")} detail={tr(locale, "Restore settings without deleting security events.", "恢复配置，安全事件记录会保留。") } />
      <div className="utility-body utility-backup-detail">
        <dl className="utility-paths"><dt>{tr(locale, "Configuration file", "配置文件")}</dt><dd>{selected?.[1].config_path || "—"}</dd><dt>{tr(locale, "Backup location", "备份位置")}</dt><dd>{selected?.[1].backup_path || "~/.qise/backups/<agent>/<timestamp>/"}</dd></dl>
        <div className="utility-operation"><h4>{tr(locale, "Latest operation", "最近操作")}</h4><pre aria-live="polite">{busy ? tr(locale, "Applying the selected backup…", "正在应用所选备份…") : output || tr(locale, "No restore operation in this session.", "本次会话尚未执行恢复操作。")}</pre></div>
      </div>
      <footer className="utility-panel-footer"><span className="utility-muted">{tr(locale, "Only agent configuration files are restored.", "仅恢复智能体配置文件。")}</span><button className="qise-action qise-action-primary" disabled={busy !== null || !selected} onClick={() => selected && restoreAgent(selected[0])}>{busy && busy !== "all" ? tr(locale, "Restoring…", "正在恢复…") : tr(locale, "Restore selected", "恢复此备份")}</button></footer>
    </section>
  </div>;
}

function eventSummary(event: SecurityEvent): string {
  const evidence = event.evidence.find((item) => item.message || item.snippet);
  return evidence?.message || evidence?.snippet || event.recommendation || event.action.resource || event.risk.category;
}

export function ObserverPage({ events, locale }: { events: SecurityEvent[]; locale: Locale }) {
  const [agent, setAgent] = useState("codex");
  const [command, setCommand] = useState("codex");
  const [cwd, setCwd] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const runtimeEvents = events.filter((event) => event.stage === "runtime");
  const totalPages = Math.max(1, Math.ceil(runtimeEvents.length / 4));
  const currentPage = Math.min(page, totalPages - 1);
  const generated = `qise run --agent ${agent}${cwd ? ` --cwd ${cwd}` : ""} -- ${command}`;
  useEffect(() => { if (selected && dialog.current && !dialog.current.open) dialog.current.showModal(); }, [selected]);
  function closeDetail() { dialog.current?.close(); setSelected(null); }
  async function copyCommand() {
    try { await navigator.clipboard.writeText(generated); setCopyStatus(tr(locale, "Copied", "已复制")); }
    catch { setCopyStatus(tr(locale, "Select and copy the command below.", "请选中下方命令手动复制。")); }
  }
  return <div className="utility-layout utility-observer-layout">
    <section className="qise-card utility-panel">
      <PanelHeader title={tr(locale, "Observe a session", "观察一个会话")} detail={tr(locale, "Build a command to run in your terminal.", "生成命令，在终端中启动观察。") } />
      <div className="utility-body utility-form"><label><span>{tr(locale, "Agent", "智能体")}</span><input className="qise-input" value={agent} onChange={(event) => { setAgent(event.target.value); setCopyStatus(""); }} /></label><label><span>{tr(locale, "Command", "启动命令")}</span><input className="qise-input" value={command} onChange={(event) => { setCommand(event.target.value); setCopyStatus(""); }} /></label><label><span>{tr(locale, "Working directory", "工作目录")}</span><input className="qise-input" value={cwd} onChange={(event) => { setCwd(event.target.value); setCopyStatus(""); }} placeholder={tr(locale, "Optional", "可选")} /></label><pre className="utility-command-preview">{generated}</pre></div>
      <footer className="utility-panel-footer"><span className="utility-muted" aria-live="polite">{copyStatus}</span><button className="qise-action qise-action-primary" onClick={copyCommand}><Icon name="code" size={15} />{tr(locale, "Copy command", "复制命令")}</button></footer>
    </section>
    <section className="qise-card utility-panel"><PanelHeader title={tr(locale, "Runtime activity", "运行时事件")} detail={tr(locale, "Select an event to inspect its details.", "点击事件，查看行为与判定详情。") }><span className="utility-count">{runtimeEvents.length}</span></PanelHeader>
      <div className="utility-list utility-runtime-list">{runtimeEvents.slice(currentPage * 4, currentPage * 4 + 4).map((event, index) => <button className="utility-event-row" key={`${event.id}-${index}`} onClick={() => setSelected(event)}><span className="utility-event-top"><time>{event.timestamp.replace("T", " ").slice(0, 19)}</time><span className={`utility-verdict utility-verdict-${(event.decision.verdict || "pass").toLowerCase()}`}>{verdictLabel(locale, event.decision.verdict || "pass")}</span></span><span className="utility-event-summary">{eventSummary(event)}</span></button>)}{!runtimeEvents.length && <EmptyState title={tr(locale, "No runtime activity yet", "暂无运行时事件")} detail={tr(locale, "Observed activity will appear here.", "启动观察后，运行中的行为会显示在这里。") } />}</div>
      <footer className="utility-panel-footer"><span className="utility-muted">{tr(locale, `${runtimeEvents.length} events`, `共 ${runtimeEvents.length} 条事件`)}</span><Pagination page={currentPage} total={totalPages} onPage={setPage} locale={locale} /></footer>
    </section>
    {selected && <dialog ref={dialog} className="utility-dialog" onCancel={closeDetail} aria-labelledby="utility-event-title"><PanelHeader title={tr(locale, "Runtime event", "运行时事件")} detail={selected.timestamp.replace("T", " ").slice(0, 19)}><button aria-label={tr(locale, "Close", "关闭")} className="utility-close" onClick={closeDetail}><Icon name="close" /></button></PanelHeader><div className="utility-dialog-body"><h4 id="utility-event-title">{eventSummary(selected)}</h4><dl className="utility-paths"><dt>{tr(locale, "Decision", "判定")}</dt><dd>{verdictLabel(locale, selected.decision.verdict || "pass")}</dd><dt>{tr(locale, "Agent", "智能体")}</dt><dd>{selected.agent.name || "—"}</dd><dt>{tr(locale, "Resource", "关联资源")}</dt><dd>{selected.action.resource || "—"}</dd></dl>{selected.evidence.map((item, index) => <p key={index}>{item.message || item.snippet || item.rule_id}</p>)}{selected.recommendation && <p>{selected.recommendation}</p>}</div><footer className="utility-panel-footer"><button className="qise-action qise-action-secondary" onClick={closeDetail}>{tr(locale, "Close details", "关闭详情")}</button></footer></dialog>}
  </div>;
}

export function IntegrationsPage({ setError, locale }: { setError: ErrorSetter; locale: Locale }) {
  const [adapter, setAdapter] = useState<(typeof ADAPTERS)[number]>("nanobot");
  const [snippet, setSnippet] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [tab, setTab] = useState<"snippet" | "runtime">("snippet");
  const [runtime, setRuntime] = useState(0);
  const requestId = useRef(0);
  async function loadSnippet(nextAdapter = adapter) {
    const request = ++requestId.current;
    setBusy(true); setCopied(false); setError(null); setSnippet("");
    try { const text = await invoke<string>("get_adapter_snippet", { adapter: nextAdapter }); if (request === requestId.current) setSnippet(text); }
    catch (error) { if (request === requestId.current) setError(String(error)); }
    finally { if (request === requestId.current) setBusy(false); }
  }
  const activeCode = tab === "runtime" ? RUNTIME_COMMANDS[runtime].command : snippet;
  async function copySnippet() {
    try { await navigator.clipboard.writeText(activeCode); setCopied(true); }
    catch (error) { setError(String(error)); }
  }
  return <div className="utility-layout utility-integration-layout">
    <section className="qise-card utility-panel"><PanelHeader title={tr(locale, "Choose an adapter", "选择适配器")} detail={tr(locale, "Connect your existing agent framework.", "为现有智能体框架添加防护。") } /><div className="utility-adapters">{ADAPTERS.map((item) => <button key={item} className={adapter === item ? "is-selected" : ""} onClick={() => { setAdapter(item); setTab("snippet"); loadSnippet(item); }} aria-pressed={adapter === item}><Icon name="code" size={17} /><span>{item}</span>{adapter === item && <Icon name="check" size={15} />}</button>)}</div><footer className="utility-panel-footer"><span className="utility-muted">{tr(locale, "Copy a snippet into your project to connect.", "复制配置片段，接入你的项目。")}</span></footer></section>
    <section className="qise-card utility-panel"><PanelHeader title={tab === "snippet" ? adapter : tr(locale, "Runtime commands", "运行命令")}><div className="qise-tabs utility-tabs"><button className={`qise-tab ${tab === "snippet" ? "is-active" : ""}`} aria-pressed={tab === "snippet"} onClick={() => { setTab("snippet"); setCopied(false); }}>{tr(locale, "Integration", "集成片段")}</button><button className={`qise-tab ${tab === "runtime" ? "is-active" : ""}`} aria-pressed={tab === "runtime"} onClick={() => { setTab("runtime"); setCopied(false); }}>{tr(locale, "Commands", "运行命令")}</button></div></PanelHeader>
      <div className="utility-body utility-code-body">{tab === "runtime" && <label className="utility-runtime-select"><span>{tr(locale, "Connection", "连接方式")}</span><select className="qise-input" value={runtime} onChange={(event) => { setRuntime(Number(event.target.value)); setCopied(false); }}>{RUNTIME_COMMANDS.map((item, index) => <option value={index} key={item.name}>{tr(locale, item.name, item.zh)}</option>)}</select></label>}<pre className="code-output utility-code" aria-live="polite">{tab === "snippet" && busy ? tr(locale, "Loading integration…", "正在加载集成片段…") : activeCode || tr(locale, "Choose an adapter or load its integration snippet.", "选择适配器，或点击加载集成片段。")}</pre></div>
      <footer className="utility-panel-footer"><span className="utility-muted">{tab === "snippet" ? tr(locale, "Integration configuration", "集成配置") : tr(locale, "Run in your terminal", "在终端中运行")}</span><div className="utility-actions">{tab === "snippet" && <button className="qise-action qise-action-secondary" disabled={busy} onClick={() => loadSnippet()}>{busy ? tr(locale, "Loading…", "加载中…") : tr(locale, "Load", "加载")}</button>}<button className="qise-action qise-action-primary" disabled={!activeCode} onClick={copySnippet}>{copied ? tr(locale, "Copied", "已复制") : tr(locale, "Copy", "复制")}</button></div></footer>
    </section>
  </div>;
}

export function AdvancedLabPage({ setError, locale }: { setError: ErrorSetter; locale: Locale }) {
  const [toolName, setToolName] = useState("bash");
  const [toolArgs, setToolArgs] = useState('{"command":"echo hello"}');
  const [pipeline, setPipeline] = useState<Pipeline>("egress");
  const [sessionId, setSessionId] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [context, setContext] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [tab, setTab] = useState<"result" | "context">("result");
  async function runCheck() {
    setBusy("check"); setError(null); setTab("result");
    try { JSON.parse(toolArgs); setResult(await invoke<unknown>("run_check", { toolName, toolArgs, pipeline, sessionId })); }
    catch (error) { setError(String(error)); }
    finally { setBusy(null); }
  }
  async function loadContext() {
    setBusy("context"); setError(null); setTab("context");
    try { if (toolArgs.trim()) JSON.parse(toolArgs); const value = await invoke<string>("get_context", { toolName, toolArgs }); setContext(value || tr(locale, "No context generated.", "没有生成上下文。")); }
    catch (error) { setError(String(error)); }
    finally { setBusy(null); }
  }
  const resultText = result === null ? tr(locale, "Run a check to inspect the guard verdict.", "运行检查，查看守卫判定。") : typeof result === "string" ? result : JSON.stringify(result, null, 2);
  return <div className="utility-layout utility-lab-layout">
    <section className="qise-card utility-panel"><PanelHeader title={tr(locale, "Sample tool call", "工具调用样例")} detail={tr(locale, "Inspect a sample before putting it into use.", "输入调用样例，检查规则如何判定。") } />
      <div className="utility-body utility-form utility-lab-form"><div className="utility-field-pair"><label><span>{tr(locale, "Tool name", "工具名称")}</span><input className="qise-input" value={toolName} onChange={(event) => setToolName(event.target.value)} /></label><label><span>{tr(locale, "Pipeline", "流水线")}</span><select className="qise-input" value={pipeline} onChange={(event) => setPipeline(event.target.value as Pipeline)}>{(["ingress", "egress", "output"] as Pipeline[]).map((item) => <option key={item} value={item}>{pipelineLabel(locale, item)}</option>)}</select></label></div><label className="utility-json-label"><span>{tr(locale, "Tool arguments · JSON", "工具参数 · JSON")}</span><textarea spellCheck={false} className="qise-input utility-json-input" value={toolArgs} onChange={(event) => setToolArgs(event.target.value)} /></label><label><span>{tr(locale, "Session ID", "会话编号")}</span><input className="qise-input" value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder={tr(locale, "Optional", "可选")} /></label></div>
      <footer className="utility-panel-footer utility-lab-actions"><button className="qise-action qise-action-secondary" disabled={busy !== null} onClick={loadContext}>{busy === "context" ? tr(locale, "Loading…", "加载中…") : tr(locale, "Get context", "获取上下文")}</button><button className="qise-action qise-action-primary" disabled={busy !== null} onClick={runCheck}>{busy === "check" ? tr(locale, "Checking…", "检查中…") : tr(locale, "Run check", "运行检查")}</button></footer>
    </section>
    <section className="qise-card utility-panel"><PanelHeader title={tr(locale, "Inspection", "检查输出")}><div className="qise-tabs utility-tabs"><button className={`qise-tab ${tab === "result" ? "is-active" : ""}`} aria-pressed={tab === "result"} onClick={() => setTab("result")}>{tr(locale, "Result", "检查结果")}</button><button className={`qise-tab ${tab === "context" ? "is-active" : ""}`} aria-pressed={tab === "context"} onClick={() => setTab("context")}>{tr(locale, "Context", "安全上下文")}</button></div></PanelHeader><div className="utility-body utility-code-body"><pre className="code-output utility-code" aria-live="polite">{busy === (tab === "result" ? "check" : "context") ? tr(locale, "Working…", "正在处理…") : tab === "result" ? resultText : context || tr(locale, "Get context to preview the security guidance.", "获取上下文，预览安全指引。")}</pre></div><footer className="utility-panel-footer"><span className="utility-muted">{tab === "result" ? tr(locale, "Verdict and evidence from the protection pipeline.", "查看防护流水线的判定与依据。") : tr(locale, "Guidance available for the selected tool call.", "查看当前工具调用可用的安全指引。")}</span></footer></section>
  </div>;
}
