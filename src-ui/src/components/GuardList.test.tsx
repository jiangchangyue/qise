import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import GuardList from "./GuardList";

describe("Guard policy controls", () => {
  it("keeps a guard shared across stages visible with one set of controls", () => {
    const html = renderToStaticMarkup(<GuardList locale="en" onSetMode={async () => undefined}
      guards={[{ name: "reasoning", pipeline: "egress/output", mode: "observe", primary_strategy: "ai" }]} />);
    expect(html.match(/>reasoning</g)).toHaveLength(1);
    expect(html.match(/data-guard-mode=/g)).toHaveLength(3);
    expect(html.match(/data-guard-mode="observe"/g)).toHaveLength(1);
    expect(html.match(/data-guard-mode="enforce"/g)).toHaveLength(1);
    expect(html.match(/data-guard-mode="off"/g)).toHaveLength(1);
    expect(html).toContain('aria-label="reasoning mode"');
  });
});
