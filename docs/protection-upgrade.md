# Smart Protection: Behavior and Upgrade Notes

This note describes the Python product engine used by the CLI and Tauri desktop app. It does not claim that the experimental Rust proxy or every SDK integration has identical coverage.

## Start Small

The desktop flow is **Safety Check → Smart Protection → Enhanced Detection (optional)**. The base runtime does not install a model, PyTorch, Ollama, or the MCP server package. Existing rule checks, asset scans, local events, and configuration recovery work without an SLM.

CLI version/help load only the modules they need. Provider YAML uses a bounded cache and a safe parser, with file-version checks on every lookup and independent copies for each instance. Rule edits, additions, replacements and deletions remain visible; this optimization does not skip checks using a time-based cache. Performance tests retain their existing budgets and use nearest-rank percentiles (the 19th sorted value for p95 of 20 samples). Warm initialization and cold startup are different measurements; filesystem latency can still affect the tail.

Smart Protection is a product preset for the existing `observe`, `enforce`, and `off` modes. `command`, `filesystem`, `network`, `credential`, and `tool_policy` default to `enforce`; other guards default to `observe`. Model installation and guard enforcement are separate choices. `observe` may report a finding but does not block the action.

## One Product Policy

```bash
qise guards --json
qise guards --set prompt observe --json
```

The first command returns the actual, deduplicated guard list. The second validates and persists a mode override in `~/.qise/guard-policy.json` (or `$QISE_HOME/guard-policy.json`). The desktop uses these same commands. Product proxy, Bridge, CLI checks and MCP refresh overrides before their next check. Standalone SDK Shields retain their explicit configuration. Bridge policy writes require a native JSON client; browser-origin requests cannot change these settings.

If a list or update fails, the desktop reports that failure instead of displaying a fabricated default policy. A malformed policy file does not silently replace the running service's last valid policy.

## Services and Agent Connections Are Different States

| Field | Meaning |
| --- | --- |
| `services_running` | The required managed services respond with the expected service identity. |
| `agent.configured` | Qise has a saved connection record that can be restored. It may be inactive or stale. |
| `agent.protected` | The managed services are healthy and the selected supported config route matches Qise. |
| `agent.protection_status` | `protected`, `needs_attention`, or `not_protected`. |
| `protection_enabled` | At least one detected agent currently satisfies the protection checks. |
| `agent.can_protect` | Automatic configuration takeover is supported for this agent. |

An open port or stale PID is insufficient service evidence. Managed health responses include service type, PID, and instance identity so an unrelated process occupying the port is not treated as Qise. This is lifecycle verification, not an authentication or operating-system isolation boundary.

A saved connection remains recoverable after its service stops or the agent is no longer detected. The desktop therefore offers **Restore** based on `configured`, not only while protection is active. Automatic updates defer while connection records remain configured, including when services are stopped.

The status check verifies known local configuration. It cannot prove that every request uses that configuration: project-level overrides, another profile, a direct API endpoint, or unsupported transports can bypass the proxy.

## Supported Connection Paths

| Agent | Product path | Boundary |
| --- | --- | --- |
| Codex | `qise protect codex` | Selected supported model-provider configuration; HTTP protocol coverage below. |
| Claude Code | `qise protect claude-code` | Anthropic Messages endpoint in the supported settings file. |
| OpenCode | `qise protect opencode` | Selected model provider in the user JSON/JSONC config; other providers are preserved. Project overrides require separate review. |
| OpenClaw | `qise protect openclaw` | Selected model provider in modern layouts, or a legacy single endpoint; ambiguous multi-provider selection is refused. |
| WorkBuddy | `qise scan agent workbuddy`, then manual setup if desired | No automatic takeover. Scans do not verify runtime routing. |
| Custom agent | `qise protect custom --base-url ...` | Starts services and prints the proxy URL; the user configures the client. Manual routing is not automatically verified. |

## Recovery and Local Data

Before takeover, Qise saves the original agent config. A repeated takeover keeps that original recovery point. Failed takeover attempts roll back their configuration changes.

Restore removes Qise's config changes and preserves unrelated user edits where possible. JSON/JSONC formatting or comments may change during rewriting. If Qise-owned provider settings have conflicting edits that cannot be safely reconciled, restore reports the conflict and leaves the current config and backup available for inspection.

`qise stop` first restores all configured agents and stops managed services only if recovery succeeds. On a restore conflict, it leaves services running so remaining clients retain their connection. You can also restore explicitly with `qise restore all` before stopping or uninstalling. Do not delete `~/.qise/` before restoring. Backups may contain inline API keys; protect them as you would the original agent config. Managed service metadata does not need to embed upstream keys in its recorded command line.

## HTTP Protocol Boundary

The Python proxy inspects OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages on supported HTTP routes. Responses includes creation and retrieval, plus SSE handling for client-executed function/custom tool calls. See the exact [coverage table](integration.md#http-protocol-coverage).

For supported streamed client tool calls, the proxy holds executable tool data until it can validate and check the completed call. Incomplete, malformed, or interrupted tool streams must not release buffered executable calls. Provider-native tools may execute upstream before Qise sees their results and are not locally gated. Text may already be delivered when its post-stream output audit runs, so that audit cannot retract a leaked secret.

WebSocket sessions, unknown API routes, hidden server conversation state, and unparsed multimodal content are outside this HTTP inspection claim. The runtime observer is a separate user-space observer, not an OS sandbox.

## Findings, Notices, and Evaluation

Events distinguish findings from precautionary or degraded-detection notices. A notice uses `info`; original evidence keeps its `evidence_kind`. A warning alone does not mean an action was stopped. Blocking depends on a blocking verdict, guard policy, and the integration honoring the decision.

Evaluation now builds isolated configurations for `rules-only`, `slm`, and `full`. Required-block samples only count as successful enforcement when actually blocked; detection metrics separately count warnings. Errors are reported instead of being treated as passes. Historical reports generated under the older mode/metric logic are not comparable evidence of current blocking quality. See [evaluation methodology](../eval/README.md).

PR CI runs Python regressions, UI tests/build, version checks, and a limited Windows/macOS metadata check. The deterministic lifecycle test uses temporary profiles, random local ports and a fake model upstream; it verifies mode changes and restoration without executing dangerous example commands. These checks do not certify real provider behavior, desktop packaging, native GUI interaction or model quality. Optional real-provider tests require explicit environment configuration.
