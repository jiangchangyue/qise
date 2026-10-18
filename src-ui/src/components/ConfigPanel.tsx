import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ReactNode } from "react";
import { tr, type Locale } from "../lib/locale";
import { describeUpdateState, type AppUpdateState, type UpdateDisplayTone } from "../lib/appUpdater";
import "./config-panel.css";

interface ModelConfig {
  base_url: string;
  model: string;
  timeout_ms: number;
  api_key: string | null;
  [key: string]: unknown;
}
interface GuardConfigEntry {
  mode: string;
  slm_confidence_threshold: number | null;
  skip_slm_on_rule_pass: boolean | null;
  slm_override_rule_warn_threshold: number | null;
  [key: string]: unknown;
}
interface ShieldConfig {
  models: { slm: ModelConfig; llm: ModelConfig };
  guards: { enabled: string[]; config: Record<string, GuardConfigEntry> };
  integration: {
    mode: string;
    proxy: {
      port: number;
      target_agents?: string[];
      auto_takeover: boolean;
      crash_recovery: boolean;
      upstream_url?: string;
      upstream_api_key?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}
type SettingsTab = "general" | "models" | "connection" | "guards";
type ModelTab = "slm" | "llm";
const guardGroups = [
  { id: "ingress", en: "Ingress", zh: "入口检查", guards: ["prompt", "tool_sanity", "context", "supply_chain"] },
  { id: "egress", en: "Execution", zh: "执行检查", guards: ["command", "filesystem", "network", "exfil", "resource", "tool_policy", "reasoning"] },
  { id: "output", en: "Output", zh: "输出检查", guards: ["credential", "audit", "output"] },
];
const guardNames: Record<string, [string, string]> = {
  prompt: ["Prompt safety", "提示词安全"], tool_sanity: ["Tool validation", "工具校验"],
  context: ["Context integrity", "上下文完整性"], supply_chain: ["Supply chain", "供应链安全"],
  command: ["Command execution", "命令执行"], filesystem: ["File access", "文件访问"],
  network: ["Network access", "网络访问"], exfil: ["Data protection", "数据外传"],
  resource: ["Resource usage", "资源使用"], tool_policy: ["Tool policy", "工具策略"],
  reasoning: ["Reasoning safety", "推理安全"], credential: ["Credentials", "凭据保护"],
  audit: ["Audit trail", "审计记录"], output: ["Output safety", "输出安全"],
};

function ConfigField({ label, children }: { label: string; children: ReactNode }) {
  return <label className="config-field"><span>{label}</span>{children}</label>;
}
function ConfigInput({ label, value, onChange, type = "text", placeholder = "", step }: {
  label: string; value: string | number; onChange: (value: string) => void;
  type?: string; placeholder?: string; step?: string;
}) {
  return <ConfigField label={label}><input className="qise-input config-input" type={type} value={value} step={step}
    onChange={(event) => onChange(event.target.value)} placeholder={placeholder}
    autoComplete={type === "password" ? "new-password" : "off"} spellCheck={false} /></ConfigField>;
}
function ConfigSelect({ label, value, options, onChange }: {
  label: string; value: string; options: { value: string; label: string }[]; onChange: (value: string) => void;
}) {
  return <ConfigField label={label}><select className="qise-input config-input" value={value} onChange={(event) => onChange(event.target.value)}>
    {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
  </select></ConfigField>;
}
function ConfigToggle({ label, description, checked, onChange }: {
  label: string; description?: string; checked: boolean; onChange: (value: boolean) => void;
}) {
  return <div className="config-toggle-row"><div><span className="config-toggle-label">{label}</span>{description && <p>{description}</p>}</div>
    <button className={`config-toggle ${checked ? "is-on" : ""}`} type="button" role="switch"
      aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}><span /></button></div>;
}
function updateToneColor(tone: UpdateDisplayTone): string {
  return { neutral: "var(--text-secondary)", blue: "var(--qise-green)", green: "var(--qise-green)",
    yellow: "var(--qise-yellow)", red: "var(--qise-red)" }[tone];
}
function ApplicationUpdateCard({ locale, state, onCheck }: {
  locale: Locale; state: AppUpdateState; onCheck: () => Promise<void>;
}) {
  const display = describeUpdateState(state, locale);
  const busy = ["checking", "downloading", "installing", "restarting"].includes(state.phase);
  return <section className="settings-update-card">
    <div className="settings-product"><div className="settings-product-mark" aria-hidden="true">Q</div><div>
      <h2>Qise</h2><p>{tr(locale, "Your AI workspace, protected.", "为你的 AI 工作提供安全保护。")}</p></div></div>
    <div className="settings-update-main"><div><h3>{tr(locale, "Application update", "应用更新")}</h3>
      <p className="settings-update-status" style={{ color: updateToneColor(display.tone) }}>{display.label}</p>
      <p className="settings-description settings-update-detail">{display.detail}</p></div>
      <button type="button" className="qise-action qise-action-secondary" onClick={() => void onCheck()} disabled={busy}>
        {state.phase === "checking" ? tr(locale, "Checking…", "正在检查…") : tr(locale, "Check for updates", "检查更新")}</button></div>
    <div className="settings-version-grid">
      <div><span>{tr(locale, "Current version", "当前版本")}</span><strong>{state.currentVersion || "—"}</strong></div>
      <div><span>{tr(locale, "Latest version", "最新版本")}</span><strong>{state.latestVersion || "—"}</strong></div></div>
    {state.phase === "downloading" && <div className="settings-progress" role="progressbar"
      aria-label={tr(locale, "Downloading update", "正在下载更新")} aria-valuenow={display.percentage ?? undefined} aria-valuemin={0} aria-valuemax={100}>
      <div style={{ width: `${display.percentage ?? 33}%` }} /></div>}
  </section>;
}
function guardModeOptions(locale: Locale) {
  return [
    { value: "observe", label: tr(locale, "Observe · log only", "观察 · 仅记录") },
    { value: "enforce", label: tr(locale, "Enforce · block risks", "拦截 · 阻止风险") },
    { value: "off", label: tr(locale, "Off · disabled", "关闭 · 不检查") },
  ];
}

export default function ConfigPanel({ locale, updateState, onCheckForUpdates }: {
  locale: Locale; updateState: AppUpdateState; onCheckForUpdates: () => Promise<void>;
}) {
  const [config, setConfig] = useState<ShieldConfig | null>(null);
  const [originalConfig, setOriginalConfig] = useState<ShieldConfig | null>(null);
  const [configPath, setConfigPath] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<SettingsTab>("general");
  const [modelTab, setModelTab] = useState<ModelTab>("slm");
  const [guardGroup, setGuardGroup] = useState(0);
  const [selectedGuard, setSelectedGuard] = useState("prompt");

  useEffect(() => { void loadConfig(); }, []);
  async function loadConfig() {
    try {
      const [loaded, path] = await Promise.all([invoke<ShieldConfig>("get_config"), invoke<string>("get_config_path")]);
      setConfig(loaded); setOriginalConfig(JSON.parse(JSON.stringify(loaded))); setConfigPath(path); setError(null);
    } catch (cause) { console.error("Failed to load config:", cause); setError(String(cause)); }
  }
  const hasChanges = Boolean(config && originalConfig && JSON.stringify(config) !== JSON.stringify(originalConfig));
  async function handleSave() {
    if (!config) return;
    const target = configPath || "~/.qise/shield.yaml";
    if (!window.confirm(tr(locale, `Save configuration to ${target}?`, `保存配置到 ${target}？`))) return;
    setSaving(true); setError(null);
    try {
      await invoke("save_config", { config }); setOriginalConfig(JSON.parse(JSON.stringify(config))); setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (cause) { setError(String(cause)); } finally { setSaving(false); }
  }
  async function handleReset() {
    try { setConfig(await invoke<ShieldConfig>("get_default_config")); setError(null); }
    catch (cause) { setError(String(cause)); }
  }
  const updateModel = (field: keyof ModelConfig, value: string | number | null) => {
    setConfig((previous) => previous ? { ...previous, models: {
      ...previous.models, [modelTab]: { ...previous.models[modelTab], [field]: value },
    } } : previous);
  };
  const updateProxy = (field: keyof ShieldConfig["integration"]["proxy"], value: string | number | boolean | string[]) => {
    setConfig((previous) => previous ? { ...previous, integration: {
      ...previous.integration, proxy: { ...previous.integration.proxy, [field]: value },
    } } : previous);
  };
  const updateGuardConfig = (field: string, value: string | number | boolean | null) => {
    setConfig((previous) => previous ? { ...previous, guards: { ...previous.guards, config: {
      ...previous.guards.config, [selectedGuard]: { ...previous.guards.config[selectedGuard], [field]: value },
    } } } : previous);
  };
  const toggleGuardEnabled = () => {
    setConfig((previous) => previous ? { ...previous, guards: { ...previous.guards,
      enabled: previous.guards.enabled.includes(selectedGuard) ? previous.guards.enabled.filter((guard) => guard !== selectedGuard)
        : [...previous.guards.enabled, selectedGuard],
    } } : previous);
  };
  const tabs: { id: SettingsTab; label: string }[] = [
    { id: "general", label: tr(locale, "General", "通用") }, { id: "models", label: tr(locale, "Models", "模型") },
    { id: "connection", label: tr(locale, "Connection", "连接") }, { id: "guards", label: tr(locale, "Guards", "守卫") },
  ];
  const model = config?.models[modelTab];
  const guard = config?.guards.config[selectedGuard];
  const guardEnabled = config?.guards.enabled.includes(selectedGuard) ?? false;
  const guardLabel = (name: string) => tr(locale, guardNames[name]?.[0] ?? name, guardNames[name]?.[1] ?? name);

  return <div className="settings-workspace">
    <nav className="qise-tabs settings-tabs" aria-label={tr(locale, "Settings sections", "设置分类")}>
      {tabs.map((item) => <button key={item.id} type="button" aria-pressed={tab === item.id}
        className={`qise-tab ${tab === item.id ? "is-active" : ""}`} onClick={() => setTab(item.id)}>{item.label}</button>)}
    </nav>
    <div className="settings-content">
      {tab === "general" && <ApplicationUpdateCard locale={locale} state={updateState} onCheck={onCheckForUpdates} />}
      {tab !== "general" && !config && <div className="settings-empty">{!error && <span className="qise-spinner qise-spinner-blue" />}
        {error ? tr(locale, "Configuration is unavailable.", "暂时无法读取配置。") : tr(locale, "Loading configuration…", "正在加载配置…")}</div>}
      {config && tab === "models" && model && <section className="settings-section">
        <div className="settings-section-heading"><div><h3>{tr(locale, "Model connection", "模型连接")}</h3>
          <p className="settings-description">{tr(locale, "Configure the models used for risk assessment.", "配置风险判断使用的模型服务。")}</p></div>
          <div className="settings-segment" aria-label={tr(locale, "Model type", "模型类型")}>
            {(["slm", "llm"] as const).map((kind) => <button type="button" key={kind} aria-pressed={modelTab === kind}
              className={modelTab === kind ? "is-selected" : ""} onClick={() => setModelTab(kind)}>
              {kind === "slm" ? tr(locale, "Small model", "小模型") : tr(locale, "Large model", "大模型")}</button>)}
          </div></div>
        <div className="settings-form-grid">
          <ConfigInput label={tr(locale, "Service URL", "服务地址")} value={model.base_url} onChange={(value) => updateModel("base_url", value)}
            placeholder={modelTab === "slm" ? "http://localhost:11434/v1" : "https://api.anthropic.com"} />
          <ConfigInput label={tr(locale, "Model name", "模型名称")} value={model.model} onChange={(value) => updateModel("model", value)}
            placeholder={modelTab === "slm" ? "qwen3:4b" : "claude-sonnet-4-5"} />
          <ConfigInput label={tr(locale, "API key · optional", "API 密钥 · 可选")} value={model.api_key ?? ""}
            onChange={(value) => updateModel("api_key", value || null)} type="password" placeholder={tr(locale, "Enter API key", "填写 API 密钥")} />
          <ConfigInput label={tr(locale, "Timeout (ms)", "超时（毫秒）")} value={model.timeout_ms}
            onChange={(value) => updateModel("timeout_ms", parseInt(value) || 0)} type="number" />
        </div>
        <div className="settings-note">{modelTab === "slm"
          ? tr(locale, "The small model performs fast, local checks on incoming requests.", "小模型用于快速检查请求，适合在本地运行。")
          : tr(locale, "The large model supports deeper analysis of complex risks.", "大模型用于复杂风险的进一步分析。")}</div>
      </section>}
      {config && tab === "connection" && <section className="settings-section">
        <div className="settings-section-heading"><div><h3>{tr(locale, "Agent connection", "智能体连接")}</h3>
          <p className="settings-description">{tr(locale, "Choose how your agents connect through Qise.", "设置智能体接入 Qise 的方式。")}</p></div></div>
        <div className="settings-form-grid settings-connection-grid">
          <ConfigSelect label={tr(locale, "Connection mode", "接入方式")} value={config.integration.mode} options={[
            { value: "proxy", label: tr(locale, "Proxy · zero-code", "代理 · 零代码接入") },
            { value: "sdk", label: tr(locale, "SDK · code integration", "SDK · 代码集成") },
            { value: "mcp", label: tr(locale, "MCP · limited support", "MCP · 有限支持") },
          ]} onChange={(mode) => setConfig((previous) => previous ? { ...previous, integration: { ...previous.integration, mode } } : previous)} />
          <ConfigInput label={tr(locale, "Proxy port", "代理端口")} value={config.integration.proxy.port}
            onChange={(value) => updateProxy("port", parseInt(value) || 8822)} type="number" />
          <ConfigInput label={tr(locale, "Upstream URL", "上游服务地址")} value={config.integration.proxy.upstream_url ?? ""}
            onChange={(value) => updateProxy("upstream_url", value)} placeholder="https://api.openai.com/v1" />
          <ConfigInput label={tr(locale, "Upstream API key", "上游 API 密钥")} value={config.integration.proxy.upstream_api_key ?? ""}
            onChange={(value) => updateProxy("upstream_api_key", value)} type="password" placeholder={tr(locale, "Optional", "可选")} />
          <ConfigInput label={tr(locale, "Target agents · comma separated", "目标智能体 · 逗号分隔")} value={(config.integration.proxy.target_agents ?? []).join(", ")}
            onChange={(value) => updateProxy("target_agents", value.split(",").map((item) => item.trim()).filter(Boolean))} placeholder="codex, openclaw" />
          <div className="settings-connection-toggles">
            <ConfigToggle label={tr(locale, "Auto takeover", "自动接管")} checked={config.integration.proxy.auto_takeover} onChange={(value) => updateProxy("auto_takeover", value)} />
            <ConfigToggle label={tr(locale, "Crash recovery", "崩溃恢复")} checked={config.integration.proxy.crash_recovery} onChange={(value) => updateProxy("crash_recovery", value)} />
          </div>
        </div>
      </section>}
      {config && tab === "guards" && <section className="settings-section settings-guards-section">
        <div className="settings-section-heading"><div><h3>{tr(locale, "Guard preferences", "守卫偏好")}</h3>
          <p className="settings-description">{tr(locale, "Adjust each checkpoint in your protection pipeline.", "按检查阶段，调整每个守卫的行为。")}</p></div>
          <div className="settings-segment" aria-label={tr(locale, "Guard stage", "检查阶段")}>
            {guardGroups.map((group, index) => <button type="button" key={group.id} aria-pressed={guardGroup === index}
              className={guardGroup === index ? "is-selected" : ""} onClick={() => { setGuardGroup(index); setSelectedGuard(group.guards[0]); }}>
              {tr(locale, group.en, group.zh)}</button>)}
          </div></div>
        <div className="settings-guard-layout">
          <nav className="settings-guard-list" aria-label={tr(locale, "Select a guard", "选择守卫")}>
            {guardGroups[guardGroup].guards.map((name) => <button type="button" key={name} aria-pressed={selectedGuard === name}
              className={selectedGuard === name ? "is-selected" : ""} onClick={() => setSelectedGuard(name)}>
              <span>{guardLabel(name)}</span><span className={`settings-guard-dot ${config.guards.enabled.includes(name) ? "is-enabled" : ""}`}
                aria-label={config.guards.enabled.includes(name) ? tr(locale, "Enabled", "已启用") : tr(locale, "Disabled", "未启用")} /></button>)}
          </nav>
          <div className="settings-guard-detail">
            <ConfigToggle label={guardLabel(selectedGuard)} description={selectedGuard} checked={guardEnabled} onChange={toggleGuardEnabled} />
            {guardEnabled ? <div className="settings-form-grid settings-guard-fields">
              <ConfigSelect label={tr(locale, "Protection mode", "保护方式")} value={guard?.mode || "observe"} options={guardModeOptions(locale)} onChange={(value) => updateGuardConfig("mode", value)} />
              {guard?.slm_confidence_threshold != null && <ConfigInput label={tr(locale, "Model confidence threshold", "模型置信度阈值")} value={guard.slm_confidence_threshold}
                onChange={(value) => updateGuardConfig("slm_confidence_threshold", parseFloat(value) || 0.7)} type="number" step="0.05" />}
              {guard?.slm_override_rule_warn_threshold != null && <ConfigInput label={tr(locale, "Warning override threshold", "覆盖规则警告阈值")} value={guard.slm_override_rule_warn_threshold}
                onChange={(value) => updateGuardConfig("slm_override_rule_warn_threshold", parseFloat(value) || 0.7)} type="number" step="0.05" />}
              {guard?.skip_slm_on_rule_pass != null && <ConfigToggle label={tr(locale, "Skip model on rule pass", "规则通过后跳过模型")} checked={guard.skip_slm_on_rule_pass}
                onChange={(value) => updateGuardConfig("skip_slm_on_rule_pass", value)} />}
            </div> : <p className="settings-guard-disabled">{tr(locale, "This guard is disabled. Enable it to configure its behavior.", "此守卫已关闭。启用后可调整保护方式。")}</p>}
          </div>
        </div>
      </section>}
    </div>
    <footer className="settings-footer">
      <div className="settings-save-state" aria-live="polite">{error
        ? <span className="settings-save-error" role="alert" title={error}>{error}</span>
        : <span className={hasChanges ? "settings-unsaved" : ""}>
          {saving ? tr(locale, "Saving changes…", "正在保存…") : saveSuccess ? tr(locale, "Configuration saved", "配置已保存") : hasChanges ? tr(locale, "Unsaved changes", "有未保存的更改") : tr(locale, "Changes are saved locally", "配置保存在本机")}
        </span>}<span className="settings-config-path" title={configPath || "~/.qise/shield.yaml"}>{configPath || "~/.qise/shield.yaml"}</span></div>
      <div className="settings-footer-actions">
        {!config && error && <button type="button" className="qise-action qise-action-secondary" onClick={() => void loadConfig()}>{tr(locale, "Retry", "重试")}</button>}
        <button type="button" className="qise-action qise-action-secondary" onClick={() => void handleReset()} disabled={!config || saving}>{tr(locale, "Restore defaults", "恢复默认")}</button>
        <button type="button" className="qise-action qise-action-primary" onClick={() => void handleSave()} disabled={!hasChanges || saving}>
          {saving ? tr(locale, "Saving…", "正在保存…") : tr(locale, "Save changes", "保存更改")}</button>
      </div>
    </footer>
  </div>;
}
