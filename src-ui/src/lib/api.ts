/** Tauri IPC API types and frontend normalization helpers. */

export interface PortStatus {
  host: string;
  port: number;
  status: string;
  detail?: string;
}

export interface ServiceStatus {
  pid?: number | null;
  port?: number;
  status?: string;
  managed_by?: string;
  command?: string;
  started_at?: string;
  upstream_url?: string;
}

export interface SlmStatus {
  configured?: boolean;
  provider?: string;
  model?: string;
  base_url?: string;
  verification?: string;
  server_running?: boolean;
  timeout_ms?: number;
  state?: Record<string, unknown>;
}

export interface AgentInfo {
  key: string;
  name: string;
  installed: boolean;
  protected: boolean;
  configured: boolean;
  can_protect: boolean;
  protection_status: "protected" | "needs_attention" | "not_protected";
  coverage?: string[];
  experimental: boolean;
  cli_path: string;
  config_path: string;
  note: string;
}

export interface ProtectedAgentRecord {
  agent?: string;
  display_name?: string;
  config_path?: string;
  backup_path?: string;
  proxy_url?: string;
  upstream_url?: string;
  protected_at?: string;
  [key: string]: unknown;
}

export interface AppStatus {
  config?: string;
  state_path?: string;
  events_path?: string;
  services?: Record<string, ServiceStatus>;
  proxy?: PortStatus;
  bridge?: PortStatus;
  slm?: SlmStatus;
  protected_agents?: Record<string, ProtectedAgentRecord>;
  detected_agents?: AgentInfo[];
  events_24h?: {
    blocked: number;
    warnings: number;
  };
  last_event?: SecurityEvent | null;
  services_running?: boolean;
  protection_enabled?: boolean;

  /** Legacy Tauri in-memory status fields kept as a temporary fallback. */
  proxy_port?: number;
  bridge_port?: number;
  blocked_count?: number;
  warning_count?: number;
  slm_status?: string;
  slm_latency_ms?: number;
}

export interface GuardInfo {
  name: string;
  mode: string;
  pipeline: string;
  primary_strategy: string;
}

export interface EventAgent {
  name: string;
  type: string;
  session_id: string;
}

export interface EventAction {
  type: string;
  name: string;
  resource: string;
}

export interface EventRisk {
  category: string;
  severity: string;
  confidence: number;
}

export interface EventDecision {
  verdict: string;
  mode: string;
  blocked_by: string[];
}

export interface EventEvidence {
  type: string;
  rule_id?: string;
  message?: string;
  path?: string;
  snippet?: string;
  guard?: string;
  verdict?: string;
  risk_source?: string;
  confidence?: number | null;
  evidence_kind?: string;
}

export interface SecurityEvent {
  id: string;
  schema_version: string;
  timestamp: string;
  stage: string;
  source: string;
  agent: EventAgent;
  action: EventAction;
  risk: EventRisk;
  decision: EventDecision;
  evidence: EventEvidence[];
  recommendation: string;
  correlation_id: string;
  raw_ref: string;
}

interface LegacySecurityEvent {
  timestamp?: string;
  guard_name?: string;
  verdict?: string;
  message?: string;
  evidence_kind?: string;
}

interface LegacyAgentInfo {
  agent_type?: string;
  display_name?: string;
  installed?: boolean;
  taken_over?: boolean;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function booleanValue(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function isNotice(verdict: string, evidenceKind: unknown): boolean {
  return verdict.toLowerCase() === "warn" && (evidenceKind === "precaution" || evidenceKind === "degraded");
}

function normalizeEvidence(value: unknown): EventEvidence {
  const raw = asRecord(value);
  const confidence = raw.confidence;
  const normalized: EventEvidence = {
    type: stringValue(raw.type, "runtime"),
    rule_id: stringValue(raw.rule_id),
    message: stringValue(raw.message),
    path: stringValue(raw.path),
    snippet: stringValue(raw.snippet),
    guard: stringValue(raw.guard),
    verdict: stringValue(raw.verdict),
    risk_source: stringValue(raw.risk_source),
    evidence_kind: stringValue(raw.evidence_kind, "finding"),
  };
  if (confidence === null || typeof confidence === "number") {
    normalized.confidence = confidence;
  }
  return normalized;
}

export function normalizeAgentInfo(value: unknown): AgentInfo {
  const raw = asRecord(value) as LegacyAgentInfo & Partial<AgentInfo>;
  const key = stringValue(raw.key, stringValue(raw.agent_type, ""));
  const name = stringValue(raw.name, stringValue(raw.display_name, key || "Unknown"));
  const configured = booleanValue(raw.configured, booleanValue(raw.taken_over, booleanValue(raw.protected)));
  // A saved takeover record is recoverable configuration, not proof that the
  // service is healthy or the agent still points at it.
  const protectedNow = raw.protection_status === "protected" && raw.protected === true;

  return {
    key,
    name,
    installed: booleanValue(raw.installed),
    protected: protectedNow,
    configured,
    can_protect: booleanValue(raw.can_protect, key !== "workbuddy"),
    protection_status: protectedNow ? "protected" : configured || raw.protection_status === "needs_attention"
      ? "needs_attention" : "not_protected",
    coverage: Array.isArray(raw.coverage) ? raw.coverage.filter((item): item is string => typeof item === "string") : [],
    experimental: booleanValue(raw.experimental),
    cli_path: stringValue(raw.cli_path),
    config_path: stringValue(raw.config_path),
    note: stringValue(raw.note),
  };
}

export function normalizeSecurityEvent(value: unknown): SecurityEvent {
  const raw = asRecord(value) as LegacySecurityEvent & Partial<SecurityEvent>;
  const decision = asRecord(raw.decision);
  const action = asRecord(raw.action);
  const risk = asRecord(raw.risk);
  const agent = asRecord(raw.agent);
  const evidence = Array.isArray(raw.evidence) ? raw.evidence : [];
  const legacyGuard = stringValue(raw.guard_name, "proxy");
  const legacyVerdict = stringValue(raw.verdict, "pass");
  const legacyMessage = stringValue(raw.message);
  const notice = isNotice(legacyVerdict, raw.evidence_kind);

  return {
    id: stringValue(raw.id, `evt_ui_${Date.now()}_${Math.random().toString(16).slice(2)}`),
    schema_version: stringValue(raw.schema_version, "0.1"),
    timestamp: stringValue(raw.timestamp, new Date().toISOString()),
    stage: stringValue(raw.stage, "runtime"),
    source: stringValue(raw.source, "desktop"),
    agent: {
      name: stringValue(agent.name),
      type: stringValue(agent.type),
      session_id: stringValue(agent.session_id),
    },
    action: {
      type: stringValue(action.type, legacyGuard),
      name: stringValue(action.name, legacyGuard),
      resource: stringValue(action.resource, legacyMessage),
    },
    risk: {
      category: stringValue(risk.category, notice ? "Protection Notice" : legacyGuard),
      severity: stringValue(risk.severity, notice ? "info" : legacyVerdict === "block" ? "high" : "medium"),
      confidence: numberValue(risk.confidence),
    },
    decision: {
      verdict: stringValue(decision.verdict, notice ? "info" : legacyVerdict),
      mode: stringValue(decision.mode, "enforce"),
      blocked_by: Array.isArray(decision.blocked_by)
        ? decision.blocked_by.map((item) => String(item))
        : [],
    },
    evidence: evidence.length ? evidence.map(normalizeEvidence) : notice ? [normalizeEvidence({
      type: "guard_result", guard: legacyGuard, verdict: legacyVerdict,
      message: legacyMessage, evidence_kind: raw.evidence_kind,
    })] : [],
    recommendation: stringValue(raw.recommendation, legacyMessage),
    correlation_id: stringValue(raw.correlation_id),
    raw_ref: stringValue(raw.raw_ref),
  };
}

export function normalizeStatus(value: unknown): AppStatus {
  const raw = asRecord(value) as AppStatus;
  const detected = Array.isArray(raw.detected_agents)
    ? raw.detected_agents.map(normalizeAgentInfo)
    : undefined;
  const lastEvent = raw.last_event ? normalizeSecurityEvent(raw.last_event) : raw.last_event;

  return {
    ...raw,
    detected_agents: detected,
    last_event: lastEvent,
  };
}

export function statusProtectionEnabled(status: AppStatus | null): boolean {
  if (!status) return false;
  if (status.protection_enabled === false) return false;
  if (status.detected_agents?.some((agent) => agent.protected && agent.protection_status === "protected")) return true;
  // This product verdict means a verified agent route, not just a running service.
  return status.protection_enabled === true;
}

export function statusHasConfiguredAgents(status: AppStatus | null): boolean {
  return Boolean(status && (
    status.detected_agents?.some((agent) => agent.configured)
    || Object.keys(status.protected_agents ?? {}).length > 0
  ));
}

export function agentAction(agent: AgentInfo): "restore" | "protect" | "manual" | "unavailable" {
  if (agent.configured) return "restore";
  if (!agent.installed) return "unavailable";
  return agent.can_protect ? "protect" : "manual";
}

export function agentStatus(agent: AgentInfo): "protected" | "needs_attention" | "available" | "missing" {
  if (agent.protected && agent.protection_status === "protected") return "protected";
  if (agent.configured || agent.protection_status === "needs_attention") return "needs_attention";
  return agent.installed ? "available" : "missing";
}

export function statusEventCounts(status: AppStatus | null): { blocked: number; warnings: number } {
  if (!status) return { blocked: 0, warnings: 0 };
  return {
    blocked: status.events_24h?.blocked ?? status.blocked_count ?? 0,
    warnings: status.events_24h?.warnings ?? status.warning_count ?? 0,
  };
}

export function portLabel(port?: PortStatus, fallbackPort?: number): string {
  const value = port?.port ?? fallbackPort;
  const state = port?.status ? ` ${port.status}` : "";
  return value ? `${value}${state}` : "unknown";
}

export function slmLabel(status: AppStatus | null): string {
  if (!status) return "unavailable";
  if (status.slm?.verification) return status.slm.verification;
  return status.slm_status ?? "unavailable";
}

export function slmTone(status: AppStatus | null): "ready" | "warn" | "off" {
  const label = slmLabel(status);
  if (label === "ready" || status?.slm_status === "local") return "ready";
  if (status?.slm?.configured || status?.slm_status === "cloud") return "warn";
  return "off";
}

export function makeRealtimeEvent(payload: Record<string, unknown>): SecurityEvent[] {
  const guardResults = Array.isArray(payload.guard_results)
    ? payload.guard_results.map((item) => asRecord(item))
    : [];
  const action = stringValue(payload.action, "pass");
  const warnings = Array.isArray(payload.warnings) ? payload.warnings.map(String) : [];
  const blockReason = stringValue(payload.block_reason);

  if (guardResults.length > 0) {
    return guardResults.map((result) => {
      const rawVerdict = stringValue(result.verdict, action);
      const notice = isNotice(rawVerdict, result.evidence_kind);
      return normalizeSecurityEvent({
        timestamp: new Date().toISOString(),
        source: "desktop",
        stage: "runtime",
        action: {
          type: "guard_event",
          name: stringValue(result.guard, "proxy"),
          resource: stringValue(result.message),
        },
        risk: {
          category: notice ? "Protection Notice" : stringValue(result.guard, "Guard"),
          severity: notice ? "info" : rawVerdict === "block" ? "high" : "medium",
          confidence: numberValue(result.confidence),
        },
        decision: {
          verdict: notice ? "info" : rawVerdict,
          mode: "enforce",
          blocked_by: stringValue(result.verdict) === "block" ? [stringValue(result.guard)] : [],
        },
        evidence: [{
          type: "guard_result",
          guard: stringValue(result.guard),
          verdict: stringValue(result.verdict),
          message: stringValue(result.message),
          evidence_kind: stringValue(result.evidence_kind, "finding"),
        }],
        recommendation: stringValue(result.message),
      });
    });
  }

  if (action === "block" || action === "warn") {
    return [normalizeSecurityEvent({
      timestamp: new Date().toISOString(),
      source: "desktop",
      stage: "runtime",
      action: {
        type: "proxy",
        name: "proxy",
        resource: blockReason || warnings.join("; "),
      },
      risk: {
        category: "Proxy",
        severity: action === "block" ? "high" : "medium",
        confidence: action === "block" ? 1 : 0.6,
      },
      decision: {
        verdict: action,
        mode: "enforce",
        blocked_by: action === "block" ? ["proxy"] : [],
      },
      evidence: warnings.map((message) => ({ type: "runtime", message })),
      recommendation: blockReason || warnings.join("; "),
    })];
  }

  return [];
}
