import { useState } from "react";
import type { GuardInfo } from "../lib/api";
import { modeLabel, pipelineLabel, tr, type Locale } from "../lib/locale";
import "./data-panels.css";

interface GuardListProps {
  guards: GuardInfo[];
  onSetMode: (guardName: string, mode: string) => Promise<void>;
  locale: Locale;
}

const MODES = ["observe", "enforce", "off"] as const;
const PAGE_SIZE = 4;
const DESCRIPTIONS: Record<string, [string, string]> = {
  prompt: ["Inspect prompts for injection and unsafe instructions.", "检测提示注入与不安全指令。"],
  tool_sanity: ["Validate tool definitions before they are used.", "在工具使用前检查其定义与行为。"],
  context: ["Check external context before it enters a session.", "检查进入会话的外部上下文。"],
  supply_chain: ["Review dependencies and downloaded resources.", "检查依赖与下载资源的供应链风险。"],
  reasoning: ["Check reasoning across action and output stages.", "跨执行与输出阶段检查推理风险。"],
  command: ["Inspect commands before they run on your computer.", "在命令执行前检查潜在风险。"],
  filesystem: ["Watch access to files and protected directories.", "检查文件操作与受保护目录访问。"],
  network: ["Inspect outbound connections and destinations.", "检查外部网络连接与目标地址。"],
  exfil: ["Identify sensitive information leaving your environment.", "识别可能离开本机的敏感信息。"],
  resource: ["Check resource usage during application execution.", "检查应用执行过程中的资源使用。"],
  tool_policy: ["Apply your policy to tool calls and arguments.", "为工具调用与参数应用安全策略。"],
  credential: ["Check output for exposed credentials and secrets.", "检测输出中泄露的凭据与密钥。"],
  audit: ["Keep a record of security decisions.", "记录安全检查与处置结果。"],
  output: ["Review model responses before they reach the application.", "在模型回复返回应用前进行检查。"],
};

export default function GuardList({ guards, onSetMode, locale }: GuardListProps) {
  const [pipeline, setPipeline] = useState("ingress");
  const [page, setPage] = useState(0);
  const [busyGuard, setBusyGuard] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function changeMode(guardName: string, mode: string) {
    setBusyGuard(guardName);
    setError(null);
    try { await onSetMode(guardName, mode); }
    catch (failure) { setError(String(failure)); }
    finally { setBusyGuard(null); }
  }

  // Shared guards keep one policy and appear under their first stage only.
  const grouped = guards.reduce((groups, guard) => {
    const key = guard.pipeline.split("/")[0];
    (groups[key] ||= []).push(guard);
    return groups;
  }, {} as Record<string, GuardInfo[]>);
  const pipelines = ["ingress", "egress", "output"].filter((key) => grouped[key]?.length);
  const activePipeline = pipelines.includes(pipeline) ? pipeline : pipelines[0];
  const activeGuards = grouped[activePipeline] || [];
  const pageCount = Math.max(1, Math.ceil(activeGuards.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleGuards = activeGuards.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const stageDescription: Record<string, string> = {
    ingress: tr(locale, "Before information reaches your application", "在外部信息进入应用前检查"),
    egress: tr(locale, "Before your application takes action", "在应用执行操作前检查"),
    output: tr(locale, "Before a response is delivered", "在回复返回应用前检查"),
  };

  return (
    <section className="qise-card guard-panel">
      <div className="guard-toolbar"><div className="qise-tabs" aria-label={tr(locale, "Inspection stage", "检查阶段")}>
        {pipelines.map((key, index) => <button key={key} className={`qise-tab ${activePipeline === key ? "is-active" : ""}`} aria-pressed={activePipeline === key} onClick={() => { setPipeline(key); setPage(0); }}><span className="guard-stage-number">0{index + 1}</span>{pipelineLabel(locale, key)}<span className="guard-tab-count">{grouped[key].length}</span></button>)}
      </div><span className="guard-total">{tr(locale, `${guards.length} guards`, `${guards.length} 个守卫`)}</span></div>
      <div className="guard-section-caption"><span>{stageDescription[activePipeline]}</span><span>{tr(locale, "Policy mode", "处置模式")}</span></div>
      {error && <p role="alert" className="guard-error">{error}</p>}
      <div className="guard-list">
        {visibleGuards.map((guard) => <div key={guard.name} className="guard-row">
          <div className="guard-identity"><div className="guard-name-line"><strong>{guard.name}</strong><span className="guard-strategy">{guard.primary_strategy === "ai" ? tr(locale, "Model assisted", "模型检查") : tr(locale, "Rule based", "规则检查")}</span>{guard.pipeline.includes("/") && <span className="guard-shared">{tr(locale, "Shared", "跨阶段")}</span>}</div><p>{DESCRIPTIONS[guard.name] ? tr(locale, ...DESCRIPTIONS[guard.name]) : tr(locale, "Apply a security policy to this inspection.", "为此项检查应用安全策略。")}</p></div>
          <div className="guard-modes" role="group" aria-label={`${guard.name} ${tr(locale, "mode", "模式")}`}>
            {MODES.map((mode) => <button key={mode} data-guard-mode={mode} aria-pressed={guard.mode === mode} className={`guard-mode ${guard.mode === mode ? "is-active" : ""}`} disabled={busyGuard !== null} onClick={() => void changeMode(guard.name, mode)}>{modeLabel(locale, mode)}</button>)}
          </div>
        </div>)}
        {visibleGuards.length === 0 && <div className="guard-empty">{tr(locale, "No guards configured.", "暂无已配置的守卫。")}</div>}
      </div>
      <footer className="guard-pagination"><span>{tr(locale, "Observe records events · Enforce blocks risks", "观察：记录事件 · 拦截：阻止风险操作")}</span><div><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} aria-label={tr(locale, "Previous page", "上一页")}>‹</button><span>{currentPage + 1} / {pageCount}</span><button disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)} aria-label={tr(locale, "Next page", "下一页")}>›</button></div></footer>
    </section>
  );
}
