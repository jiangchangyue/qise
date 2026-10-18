import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import AgentPanel from "./AgentPanel";
import { normalizeAgentInfo } from "../lib/api";

function renderAgent(agent: unknown) {
  return renderToStaticMarkup(<AgentPanel agents={[normalizeAgentInfo(agent)]}
    task={{ status: "idle" }} onProtect={() => undefined} onRestore={() => undefined} locale="zh" />);
}

describe("AgentPanel recovery and manual connection", () => {
  it("renders a restore action for an inactive configured Agent", () => {
    const html = renderAgent({ key: "codex", name: "Codex", installed: false, configured: true,
      protected: false, protection_status: "needs_attention", can_protect: true });
    expect(html).toContain("保护需修复");
    expect(html).toContain("恢复</button>");
    expect(html).not.toContain("已保护");
  });

  it("explains manual connection without offering automatic protection", () => {
    const html = renderAgent({ key: "workbuddy", name: "WorkBuddy", installed: true,
      configured: false, protected: false, protection_status: "not_protected", can_protect: false });
    expect(html).toContain("需手动接入");
    expect(html).not.toContain("保护</button>");
  });
});
