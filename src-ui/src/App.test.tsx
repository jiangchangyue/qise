import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { HomePage } from "./App";
import { normalizeStatus, type AppStatus } from "./lib/api";

function renderHome(status: AppStatus | null) {
  return renderToStaticMarkup(<HomePage status={status} guards={[]} agents={status?.detected_agents ?? []}
    onOpen={() => undefined} onDetectAgents={() => undefined} onQuickScan={() => undefined}
    detectingAgents={false} scanning={false} locale="zh" />);
}

describe("Home protection claims", () => {
  it("offers a safety check without claiming stopped protection is running", () => {
    const html = renderHome(normalizeStatus({ protection_enabled: false, services_running: false, detected_agents: [] }));
    expect(html).toContain("一键安全体检");
    expect(html).toContain("智能保护未开启");
    expect(html).toContain("保护服务已停止");
    expect(html).not.toContain("当前使用本地规则保护");
  });

  it("does not equate ready services with a verified agent connection", () => {
    const html = renderHome(normalizeStatus({ protection_enabled: false, services_running: true, detected_agents: [] }));
    expect(html).toContain("服务已就绪，等待接入");
    expect(html).toContain("手动接入需自行检查路由");
    expect(html).not.toContain("智能保护已开启");
  });

  it("shows uncertainty when runtime status could not be loaded", () => {
    const html = renderHome(null);
    expect(html).toContain("保护状态待确认");
    expect(html).not.toContain("智能保护已开启");
  });

  it("shows recovery guidance for a configured Agent whose service stopped", () => {
    const html = renderHome(normalizeStatus({ protection_enabled: false, detected_agents: [{
      key: "codex", name: "Codex", installed: true, configured: true, protected: false,
      protection_status: "needs_attention", can_protect: true,
    }] }));
    expect(html).toContain("保护需要修复");
    expect(html).toContain("恢复原设置或重新接入");
    expect(html).not.toContain("当前使用本地规则保护");
  });
});
