# Integration Guide

The desktop and `qise` CLI manage the same Python product engine. Choose the path based on where you can enforce a check, then confirm that the actual agent traffic or tool invocation reaches it.

| Path | Setup | What Qise can check |
| --- | --- | --- |
| Product HTTP proxy | Supported agent takeover or manual base-URL configuration | Parsed requests and responses on supported HTTP routes. |
| MCP tools | Install the optional MCP package and register Qise manually | Content or tool calls explicitly submitted to Qise's tools. |
| SDK/adapters | Add checks to your application or tool wrappers | The hooks and tool invocations you connect. |

No path by itself provides an operating-system sandbox or complete coverage of every agent action.

## Product Proxy

```text
Agent → local Qise HTTP proxy → existing model API
                  ↓
          policy checks + events
```

Start with a scan, then connect a supported installed agent:

```bash
qise scan all
qise protect codex
# Other supported choices: opencode, openclaw, claude-code
qise status --json
```

Qise backs up the agent config, determines the upstream, changes the supported selected route, and records recovery metadata. Supply `--base-url` if upstream selection is ambiguous. OpenCode and OpenClaw selected-provider changes preserve other providers. Project-level overrides or alternative profiles may still route around the user config.

`configured` means recovery metadata exists; `protected` additionally requires matching config and healthy managed services. The health check identifies the expected service instance instead of trusting any process on the port. See [status and recovery](protection-upgrade.md).

### Manual Clients and WorkBuddy

WorkBuddy supports asset scans, not automatic takeover:

```bash
qise scan agent workbuddy
qise protect custom --base-url https://api.example.com/v1
```

Set your client's supported HTTP API base URL to the local URL printed by Qise, usually `http://127.0.0.1:8822/agent/custom/v1`. Keep the normal upstream credentials configured appropriately for that provider. A successful service start does not confirm this manual client setup, and Qise does not automatically verify the manual route.

For advanced standalone proxy use, global config options precede the command:

```bash
qise --config shield.yaml proxy start --port 8822 --upstream https://api.example.com/v1
```

### HTTP Protocol Coverage

This table applies to the Python product proxy.

| Protocol/route | Inspected behavior | Boundary |
| --- | --- | --- |
| `POST /v1/chat/completions` | Supported message/tool input, response tool calls, text output, and SSE tool-call assembly. | OpenAI-compatible providers can differ in fields and streaming behavior. |
| `POST /v1/messages` | Anthropic message/tool input, response `tool_use`, and SSE tool-call assembly. | Provider-native tools are not made local by routing through Qise. |
| `POST /v1/responses` | Supported input items and function/custom-tool output, including SSE. | Hidden context referenced by `previous_response_id` is not fully available for inspection. |
| `GET /v1/responses/{id}` | Retrieved supported output and SSE when requested. | Only returned content is available for checks. |
| Other HTTP routes | May be forwarded for compatibility. | Forwarding is not a claim of guard coverage. |
| WebSocket | Not supported by this HTTP inspection path. | Configure a supported HTTP transport or use explicit application hooks. |

Image/audio payloads and unsupported item types are not covered by a general semantic-content inspection claim. The proxy must receive the actual request; direct upstream traffic cannot be inspected.

### Streaming and Execution

Supported client-executed tool calls are buffered until complete, validated, and checked before executable call data is delivered to the agent. Malformed/incomplete tool streams and interrupted streams do not count as successful checks or release buffered executable calls. This gate covers delivery of supported client tools, not tools that the model provider executes on its own servers.

Streaming text can be forwarded before the final output audit. A later warning or block verdict cannot retract text already delivered. Do not treat post-stream credential detection as guaranteed prevention of streamed disclosure.

### Policy and Decisions

```bash
qise guards --json
qise guards --set prompt observe --json
```

The desktop uses these commands too. Mode overrides persist in `~/.qise/guard-policy.json` and product proxy/Bridge checks refresh them without restart. `enforce`, `observe`, and `off` remain the only modes; Smart Protection is a preset. Models are optional and their presence does not change modes automatically.

| Effective outcome | Meaning |
| --- | --- |
| Pass | The checked content may proceed. |
| Warning | Report the finding; continue under the effective policy. |
| Block | The integration must honor `should_block`; the proxy refuses the checked request or tool call. |
| Info | Precautionary guidance or degraded-detection notice, not a confirmed finding. |

### Restore Before Stopping

```bash
qise restore all
qise stop
```

Restore removes Qise changes while preserving unrelated edits where possible. Conflicting changes that cannot be reconciled safely produce an error and keep the current config and backup. `qise stop` also restores all configured clients before stopping services; if recovery fails, it keeps services running.

## MCP Tools

MCP is an optional server dependency, separate from scanning MCP config files:

```bash
pip install -e ".[mcp]"
qise serve --transport stdio
```

Register the server in your client's MCP settings manually, using the `qise` executable from the environment where it is installed:

```json
{
  "mcpServers": {
    "qise": {
      "command": "/absolute/path/to/qise",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

Available tools include `qise_check_tool_call`, `qise_check_content`, `qise_check_output`, and `qise_get_security_context`. They check only submitted data. Merely registering the server or asking an agent to call it does not enforce interception of other tools. The application must require the check and honor blocking results for it to serve as a gate.

## SDK and Adapters

Use the SDK when you control the application boundary. For example:

```python
from qise import Shield
from qise.core.models import GuardContext

shield = Shield.from_config()
result = shield.check_sync(
    GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"}),
    pipeline_kind="egress",
)
if result.should_block:
    raise RuntimeError(f"Blocked by Qise: {result.blocked_by}")
# Only invoke the real tool after accepting the result.
```

Inspect the current integration snippets rather than assuming all frameworks share a hook API:

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

Adapters cover only installed hooks or wrapped tools. Framework packages and real-provider examples are optional; local mock regressions do not prove compatibility with every released framework version. An independent SDK `Shield` uses its own configuration rather than automatically adopting product CLI policy overrides.

## Verification

Run the normal offline regression suite with development dependencies:

```bash
pip install -e ".[dev,proxy]"
pytest tests
```

Model-dependent checks may skip without their optional prerequisites. `scripts/e2e_tauri_test.py` is a live CLI/service smoke test, not an automated GUI test. Set `QISE_E2E_MODEL` and, for an authenticated upstream, `QISE_E2E_API_KEY`; SLM checks are explicitly opt-in. See its `--help` before running it against a provider.

Review [evaluation methodology](../eval/README.md) before interpreting detection or blocking scores. Historical E2E counts and evaluation reports are not a current compatibility guarantee.
