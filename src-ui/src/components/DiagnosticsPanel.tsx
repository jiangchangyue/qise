import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AppStatus, normalizeStatus, slmLabel, statusProtectionEnabled } from "../lib/api";
import { portStatusLabel, slmStatusLabel, statusWord, tr, type Locale } from "../lib/locale";

import Icon from "./Icon";

interface DoctorCheck {
  name: string;
  status: string;
  detail: string;
}

interface DoctorReport {
  result: string;
  checks: DoctorCheck[];
  warnings: string[];
  errors: string[];
}

interface SlmReport {
  configured: boolean;
  provider: string;
  model: string;
  base_url: string;
  verification: string;
  server_running: boolean;
  timeout_ms: number;
  config_path?: string;
}

function statusTone(status: string): string {
  const normalized = status.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (["ok", "ready", "available"].includes(normalized)) return "badge-pass";
  if (["warning", "warn", "ready_with_warnings", "not_configured", "busy"].includes(normalized)) return "badge-warn";
  return "badge-block";
}

function DetailRow({
  label,
  value,
  tone,
  locale,
}: {
  label: string;
  value: string;
  tone?: string;
  locale: Locale;
}) {
  return <div className="diagnostic-row"><span>{label}</span><strong title={value}>{value || statusWord(locale, "unknown")}</strong>{tone && <span className={statusTone(tone)}>{statusWord(locale,tone)}</span>}</div>;

}

export default function DiagnosticsPanel({ locale }: { locale: Locale }) {
  const [doctor, setDoctor] = useState<DoctorReport | null>(null);
  const [slm, setSlm] = useState<SlmReport | null>(null);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDiagnostics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [doctorReport, slmReport, statusReport] = await Promise.all([
        invoke<DoctorReport>("get_doctor"),
        invoke<SlmReport>("get_slm_status"),
        invoke<unknown>("get_status"),
      ]);
      setDoctor(doctorReport);
      setSlm(slmReport);
      setStatus(normalizeStatus(statusReport));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDiagnostics();
  }, [loadDiagnostics]);

  const checks = useMemo(() => {
    const byName = new Map<string, DoctorCheck>();
    doctor?.checks.forEach((check) => byName.set(check.name, check));
    return byName;
  }, [doctor]);

  const qiseVersion = checks.get("Qise")?.detail ?? "unknown";
  const pythonVersion = checks.get("Python")?.detail ?? "unknown";
  const config = checks.get("Config");
  const eventLog = checks.get("Event log");
  const upstream = checks.get("Upstream");
  const proxy = checks.get("Proxy port");
  const bridge = checks.get("Bridge port");

  return <section className="workspace-panel diagnostic-workspace">
    <div className="workspace-panel-header"><Icon name="activity" size={20}/><h2>{tr(locale,"Environment overview","运行环境概况")}</h2><button className="qise-action qise-action-secondary" disabled={loading} onClick={loadDiagnostics}><Icon name="refresh" size={13}/>{loading ? tr(locale,"Checking…","检查中…") : tr(locale,"Run diagnostics","重新检查")}</button></div>
    {error ? <div className="empty-workspace"><h3>{tr(locale,"Unable to load diagnostics","暂时无法获取诊断结果")}</h3><p role="alert">{error}</p></div> : <div className="diagnostic-body">
      <div className="diagnostic-summary"><span className="diagnostic-symbol"><Icon name="activity" size={24}/></span><div><h3>{doctor ? statusWord(locale,doctor.result) : tr(locale,"Checking…","正在检查…")}</h3><p>Qise {qiseVersion} <span>·</span> Python {pythonVersion}</p></div>{doctor && <span className={statusTone(doctor.result)}>{tr(locale,"Local environment","本地环境")}</span>}</div>
      <div className="diagnostic-grid">
        <div><h3>{tr(locale,"Connections","保护连接")}</h3><DetailRow locale={locale} label={tr(locale,"Protection","保护状态")} value={statusProtectionEnabled(status) ? statusWord(locale,"protected") : statusWord(locale,"unprotected")} /><DetailRow locale={locale} label={tr(locale,"Proxy","代理")} value={status ? portStatusLabel(locale,status.proxy,status.proxy_port ?? 8822) : proxy?.detail ?? ""} tone={proxy?.status}/><DetailRow locale={locale} label={tr(locale,"Bridge","桥接")} value={status ? portStatusLabel(locale,status.bridge,status.bridge_port ?? 8823) : bridge?.detail ?? ""} tone={bridge?.status}/><DetailRow locale={locale} label={tr(locale,"Upstream","上游")} value={upstream?.detail ?? ""} tone={upstream?.status}/></div>
        <div><h3>{tr(locale,"Configuration & models","配置与模型")}</h3><DetailRow locale={locale} label={tr(locale,"Config","配置")} value={status?.config ?? config?.detail ?? ""} tone={config?.status}/><DetailRow locale={locale} label={tr(locale,"Events","事件")} value={status?.events_path ?? eventLog?.detail ?? ""} tone={eventLog?.status}/><DetailRow locale={locale} label={tr(locale,"Model review","模型审查")} value={slm ? `${slmStatusLabel(locale,slm.verification)} · ${slm.model || slm.provider}` : slmStatusLabel(locale,slmLabel(status))} tone={slm?.verification}/><DetailRow locale={locale} label={tr(locale,"Model config","模型配置")} value={slm?.config_path ?? ""}/></div>
      </div>
      {doctor && (doctor.errors.length > 0 || doctor.warnings.length > 0) && <div className="diagnostic-notices">{doctor.errors.map((item,i)=><p key={`e${i}`} className="text-qise-red">{item}</p>)}{doctor.warnings.map((item,i)=><p key={`w${i}`}>{item}</p>)}</div>}
    </div>}
    <div className="workspace-panel-footer"><span className="subtle-label">{tr(locale,"Diagnostics reads current status without changing your configuration.","诊断只读取当前状态，不会修改你的配置。")}</span></div>
  </section>;
}
