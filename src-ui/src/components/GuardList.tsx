import { useState } from "react";
import type { GuardInfo } from "../lib/api";
import { modeLabel, pipelineLabel, tr, type Locale } from "../lib/locale";

interface GuardListProps {
  guards: GuardInfo[];
  onSetMode: (guardName: string, mode: string) => Promise<void>;
  locale: Locale;
}

const MODES = ["observe", "enforce", "off"] as const;

function modeBadgeClass(mode: string): string {
  switch (mode) {
    case "enforce":
      return "badge-block";
    case "observe":
      return "badge-warn";
    case "off":
      return "badge-pass";
    default:
      return "badge-pass";
  }
}

function guardModeBtnClass(mode: string, active: boolean): string {
  if (!active) return "qise-guard-mode-btn qise-guard-mode-btn-inactive";
  switch (mode) {
    case "observe":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-observe";
    case "enforce":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-enforce";
    case "off":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-off";
    default:
      return "qise-guard-mode-btn qise-guard-mode-btn-inactive";
  }
}

const PIPELINE_ICONS: Record<string, string> = {
  ingress: "↓",
  egress: "↑",
  output: "⊙",
};

const PIPELINE_ICON_CLASSES: Record<string, string> = {
  ingress: "qise-pipeline-ingress",
  egress: "qise-pipeline-egress",
  output: "qise-pipeline-output",
};

export default function GuardList({ guards, onSetMode, locale }: GuardListProps) {
  const [busyGuard, setBusyGuard] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function changeMode(guardName: string, mode: string) {
    setBusyGuard(guardName);
    setError(null);
    try {
      await onSetMode(guardName, mode);
    } catch (failure) {
      setError(String(failure));
    } finally {
      setBusyGuard(null);
    }
  }
  // Group by pipeline
  const grouped = guards.reduce(
    (acc, g) => {
      // A shared guard has one policy, even when it checks several stages.
      const key = g.pipeline.split("/")[0];
      if (!acc[key]) acc[key] = [];
      acc[key].push(g);
      return acc;
    },
    {} as Record<string, GuardInfo[]>,
  );

  return (
    <div className="space-y-6">
      {error && <p role="alert" className="text-sm text-qise-red">{error}</p>}
      {["ingress", "egress", "output"].map((pipeline) => {
        const pipelineGuards = grouped[pipeline];
        if (!pipelineGuards) return null;
        const icon = PIPELINE_ICONS[pipeline] || "";
        const iconClass = PIPELINE_ICON_CLASSES[pipeline] || "";

        return (
          <div key={pipeline}>
            <div className="qise-pipeline-header">
              <span className={`qise-pipeline-icon ${iconClass}`}>{icon}</span>
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                {pipelineLabel(locale, pipeline)}
              </h3>
              <span className="text-xs text-[var(--text-dim)]">
                {pipelineGuards.length} {tr(locale, "guards", "个守卫")}
              </span>
            </div>
            <div className="space-y-1">
              {pipelineGuards.map((guard) => (
                <div key={guard.name} className="qise-guard-row">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                      {guard.name}
                    </span>
                    <span className={modeBadgeClass(guard.mode)}>
                      <span className="badge-dot" />
                      {modeLabel(locale, guard.mode)}
                    </span>
                    <span className="rounded-full bg-white px-2 py-1 text-[11px] font-mono text-[var(--text-dim)] ring-1 ring-[var(--border-subtle)]">
                      {guard.primary_strategy === "ai" ? tr(locale, "AI first", "模型优先") : tr(locale, "Rules", "规则")}
                    </span>
                  </div>
                  <div className="flex gap-1">
                    {MODES.map((mode) => (
                      <button
                        key={mode}
                        className={guardModeBtnClass(mode, guard.mode === mode)}
                        disabled={busyGuard !== null}
                        onClick={() => void changeMode(guard.name, mode)}
                      >
                        {modeLabel(locale, mode)}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
