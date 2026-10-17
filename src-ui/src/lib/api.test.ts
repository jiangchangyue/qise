import { describe, expect, it } from "vitest";
import {
  agentAction,
  agentStatus,
  normalizeAgentInfo,
  makeRealtimeEvent,
  normalizeSecurityEvent,
  normalizeStatus,
  statusHasConfiguredAgents,
  statusProtectionEnabled,
} from "./api";

function connectedAgent(overrides: Record<string, unknown> = {}) {
  return normalizeAgentInfo({
    key: "codex", name: "Codex", installed: true,
    configured: true, can_protect: true,
    protected: true, protection_status: "protected",
    ...overrides,
  });
}

describe("Agent protection state", () => {
  it("keeps a stopped configured Agent recoverable without claiming protection", () => {
    const agent = connectedAgent({ protected: false, protection_status: "needs_attention" });
    const status = { detected_agents: [agent], protected_agents: { codex: { backup_path: "/backup" } } };
    expect(agentStatus(agent)).toBe("needs_attention");
    expect(agentAction(agent)).toBe("restore");
    expect(statusProtectionEnabled(status)).toBe(false);
    expect(statusHasConfiguredAgents(status)).toBe(true);
  });

  it("offers restore even after the configured Agent is no longer detected", () => {
    const agent = connectedAgent({ installed: false, protected: false, protection_status: "needs_attention" });
    expect(agentAction(agent)).toBe("restore");
  });

  it("does not treat legacy takeover records as health evidence", () => {
    const agent = normalizeAgentInfo({ agent_type: "codex", installed: true, taken_over: true });
    expect(agent.configured).toBe(true);
    expect(agent.protected).toBe(false);
    expect(agentStatus(agent)).toBe("needs_attention");
    expect(statusProtectionEnabled({ protected_agents: { codex: {} } })).toBe(false);
  });

  it("requires both backend health verdict and protected flag", () => {
    expect(connectedAgent({ protected: false }).protected).toBe(false);
    expect(connectedAgent({ protection_status: "needs_attention" }).protected).toBe(false);
    expect(statusProtectionEnabled({ detected_agents: [connectedAgent()] })).toBe(true);
    expect(statusProtectionEnabled({ protection_enabled: false, detected_agents: [connectedAgent()] })).toBe(false);
  });

  it("supports the backend's explicit verified protection verdict", () => {
    expect(statusProtectionEnabled({ protection_enabled: true })).toBe(true);
    expect(statusProtectionEnabled(null)).toBe(false);
  });

  it("keeps WorkBuddy on the manual connection path", () => {
    const agent = normalizeAgentInfo({ key: "workbuddy", installed: true, can_protect: false });
    expect(agentAction(agent)).toBe("manual");
    expect(agent.protected).toBe(false);
    expect(normalizeAgentInfo({ key: "workbuddy", installed: true }).can_protect).toBe(false);
  });

  it("only offers automatic protection for an installed supported Agent", () => {
    expect(agentAction(connectedAgent({ configured: false, protected: false, protection_status: "not_protected" }))).toBe("protect");
    expect(agentAction(normalizeAgentInfo({ key: "opencode", installed: false }))).toBe("unavailable");
  });

  it("normalizes detected Agent capabilities and coverage in status replies", () => {
    const status = normalizeStatus({ detected_agents: [{ key: "workbuddy", installed: true, can_protect: false,
      coverage: ["Manual connection required", 42] }] });
    expect(status.detected_agents?.[0].coverage).toEqual(["Manual connection required"]);
    expect(status.detected_agents?.[0].can_protect).toBe(false);
  });
});

describe("Protection notices", () => {
  it("keeps explicit precaution/degraded warnings informational without hiding findings or blocks", () => {
    const notices = makeRealtimeEvent({ guard_results: [
      { guard: "reasoning", verdict: "warn", evidence_kind: "precaution" },
      { guard: "prompt", verdict: "warn", evidence_kind: "degraded" },
      { guard: "prompt", verdict: "warn", evidence_kind: "finding" },
      { guard: "command", verdict: "block", evidence_kind: "degraded" },
      { guard: "network", verdict: "warn" },
    ] });
    expect(notices.map((event) => event.decision.verdict)).toEqual(["info", "info", "warn", "block", "warn"]);
    expect(notices[0].risk.severity).toBe("info");
    expect(notices[0].evidence[0].verdict).toBe("warn");
    expect(notices[0].evidence[0].evidence_kind).toBe("precaution");
    const bridge = normalizeSecurityEvent({ guard_name: "prompt", verdict: "warn", evidence_kind: "degraded", message: "Model unavailable" });
    expect(bridge.decision.verdict).toBe("info");
    expect(bridge.evidence[0].evidence_kind).toBe("degraded");
  });
});
