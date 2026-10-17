<div align="center">

<img src=src-tauri/icons/logo-2.png width="36%"/> 

**Shanghai Innovation Institute (SII) | Fudan University**

**Local-First Security for AI Agents.**

Qise helps you use agents such as Codex, OpenClaw, Claude Code, OpenCode, and custom agents with a local safety layer. It can scan risky integrations, route model traffic through a guard proxy, block dangerous actions, and show a readable local event trail.

[中文](./README_CN.md) | [Quickstart](./docs/quickstart.md) | [Install](./docs/install.md) | [Architecture](./docs/architecture.md) | [Privacy](./docs/privacy.md)

</div>

> [!IMPORTANT]
> This project is still under active development and may contain bugs. Contributions via Issues and PRs are welcome.
---

## Start Here

Qise has three entry points:

| You are | Start with | Why |
| --- | --- | --- |
| A regular agent user | Desktop App | Detect agents, protect them, scan configs, and read events without memorizing commands. |
| A terminal/CLI user | `qise` CLI | Run scans, protect agents, inspect events, and automate checks from scripts. |
| An agent developer | SDK / adapters | Add Qise checks inside LangGraph, OpenAI Agents SDK, Nanobot, Hermes, or NexAU. |

The desktop app and CLI use the same Python Qise product engine. Start with **Safety Check**, then connect a supported agent through **Smart Protection**. **Enhanced Detection** is optional: scans, deterministic rules, events, and configuration recovery work without Ollama, a model download, or a GPU.

Smart Protection is a preset, not a fourth guard mode. It enforces the default command, filesystem, network, credential, and tool-policy rules while semantic guards observe by default. Adding a model does not automatically turn every warning into a block. See [protection behavior and upgrade notes](./docs/protection-upgrade.md).

## What Qise Does

<div align="center"> 
<img src=docs/qise-frame.png width="88%"/>
</div>

AI coding agents can read files, run shell commands, call MCP servers, install skills, use memories, and send data to model APIs. That power is useful, but it creates a new local security boundary: poisoned tool descriptions, malicious skills, prompt injection, unsafe commands, and accidental secret leaks can become real machine-level risk.

Qise runs on your machine beside the agent you already use. It is not a model provider and it does not replace your agent.

In the common proxy mode, the flow is:

```text
AI Agent -> Qise local proxy -> your existing model API
```

Qise can:

- Detect supported agents such as Codex, OpenClaw, Claude Code, and OpenCode; scan WorkBuddy assets and guide manual connection.
- Back up an agent config before changing it.
- Route the agent through a local guard proxy.
- Check supported client-executed tool calls before the proxy delivers them to the agent.
- Block dangerous commands such as destructive shell operations.
- Warn about suspicious file, network, credential, and exfiltration behavior.
- Scan skills, MCP configs, and agent configs before you trust them.
- Add local security context to agent/model requests.
- Record local JSONL security events with risk, evidence, verdict, and recommendation.
- Optionally use a local small language model through Ollama or another OpenAI-compatible endpoint as a second semantic review layer.

Qise is local-first. Product state, backups, and events are stored under `~/.qise/` by default. Event records store compact evidence snippets, not full model traffic.

<div align="center"> 
<img src=docs/qise_main.png width="88%"/>
</div>

## Current Status

Qise is currently an alpha/MVP project. Desktop builds are distributed through GitHub Releases for Windows x64 and macOS Apple Silicon. Tauri updater artifacts are signed, but Windows Authenticode signing and Apple Developer ID notarization are still future release-hardening work.

| Area | What works now | Status |
| --- | --- | --- |
| Desktop app | Tauri 2 + React UI over the same Qise CLI/product engine | Source-build MVP |
| CLI | `doctor`, `status`, `agents`, `scan`, `check`, `events`, `protect`, `restore`, `stop`, `slm`, `run` | Active MVP |
| Proxy protection | HTTP Chat Completions, Responses, and Anthropic Messages; see the [protocol boundaries](./docs/integration.md#http-protocol-coverage) | Active MVP |
| Claude Code | Native Anthropic Messages proxy with request/response parsing, security-context injection, and streaming `tool_use` checks | Active MVP |
| Preflight scan | Skill, MCP config, agent config, and detected agent asset scanning | Active MVP |
| Guard engine | 14 guard categories across ingress, egress, and output pipelines | Active MVP |
| Event log | Local JSONL events with risk, evidence, verdict, recommendation, and correlation IDs | Active MVP |
| Local SLM | Optional semantic review layer through Ollama or custom OpenAI-compatible endpoint | Active MVP |
| Runtime Observer | User-space wrapper for process, stdout/stderr, file diff, and best-effort network evidence | MVP |
| SDK/adapters | Framework adapters for Nanobot, Hermes, NexAU, LangGraph, and OpenAI Agents SDK | Developer MVP |

## Install The Desktop App

The desktop app is the easiest way to try Qise as a product. It gives you pages for protection status, agent detection, one-click protection, preflight scanning, event logs, guard rules, local SLM setup, backups, diagnostics, and SDK snippets.

### Option A: Install A Prebuilt App From GitHub Releases

Open the [latest Qise release](https://github.com/WhitzardAgent/qise/releases/latest) and download:

```text
macOS Apple Silicon: Qise_*_aarch64.dmg
Windows x64:         Qise_*_x64-setup.exe
```

On macOS:

1. Open the downloaded `Qise_*_aarch64.dmg`.
2. Drag `Qise.app` into `Applications`.
3. Open `Qise.app`.

If macOS blocks the first launch because the build is not notarized yet, right-click `Qise.app`, choose `Open`, then confirm. You can also allow it from `System Settings -> Privacy & Security`.

On Windows:

1. Open the downloaded `Qise_*_x64-setup.exe`.
2. Complete the installer wizard.
3. Open Qise from the Start menu.

The Windows test installer is not signed yet, so Windows SmartScreen may show an unknown-publisher warning.

This Qise 0.2.0 build is the first updater-enabled build. Users who installed an earlier 0.2.0 build must install this build manually once because automatic updates require a higher version number. Later stable releases are checked after startup. Automatic installation is deferred while protection state is unknown or an agent still has a Qise connection configured, including when its service has stopped. Update status and manual checking are available under `Settings -> Application Update`.

### Option B: Build The macOS App From Source

Run these commands from a terminal:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,proxy]"
python -m pip install pyinstaller
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri build
```

What each command does:

| Command | Why you run it |
| --- | --- |
| `git clone ...` | Downloads the Qise source code. |
| `cd qise` | Moves into the project directory. |
| `python3.11 -m venv .venv` | Creates an isolated Python environment. |
| `source .venv/bin/activate` | Makes `python` and `pip` use that environment. |
| `pip install -e ".[dev,proxy]"` | Installs the Qise CLI/product engine and development/proxy dependencies. |
| `python -m pip install pyinstaller` | Installs the tool used to bundle the Python Qise runtime into the desktop app. |
| `npm --prefix src-ui install` | Installs React, Vite, TypeScript, and Tauri frontend dependencies. |
| `src-ui/node_modules/.bin/tauri build` | Builds the bundled Qise runtime, React UI, `.app`, and `.dmg`. |

After a successful build, the important files are:

```text
src-tauri/target/release/bundle/macos/Qise.app
src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg
```

The exact DMG suffix can vary by version and CPU architecture. On Apple Silicon, it is commonly `aarch64`.

To install the locally built app:

1. Open `src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg`.
2. Drag `Qise.app` into `Applications`.
3. Open `Qise.app`.


The manual `Build Windows Desktop Test Installer` workflow remains available for test artifacts. It does not publish a release or commit generated installers into `main`.

### Run The Desktop App In Development Mode

Use this when you are editing the UI or testing quickly:

```bash
source .venv/bin/activate
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri dev
```

## First Use In The Desktop App

1. Open Qise and click **Run Safety Check** on the home page.
2. Review the findings for agent configuration, skills, and MCP assets.
3. Open **Smart Protection** and choose a supported agent.
4. Check the upstream model API URL, then click **Protect**.
5. Confirm that the agent is shown as protected, then use it normally.
6. Read warnings and blocks in **Security Events**. Enable **Enhanced Detection** only if you want model review.

A scan is a point-in-time configuration review; it does not turn on runtime protection. A service being ready also does not prove that an agent uses it. An existing connection can be marked **Needs attention** when services stop or its configuration no longer matches; **Restore** remains available in that state.

For Claude Code, keep your Anthropic key available in the environment:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

The Claude Code upstream is normally:

```text
https://api.anthropic.com
```

To undo Qise changes from the desktop app, use `Backup & Restore` or `Agent Shield`. From the CLI, use:

```bash
qise restore all
qise stop
```

## Install The CLI From Source

If you prefer the terminal, install Qise as a Python package. The base package has no model runtime or MCP server dependency; `[proxy]` adds optional config watching:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor # Checks Python, Qise import, config, local ports, event log, optional SLM, and detected agents.
```

<!-- What each command does:

| Command | Why you run it |
| --- | --- |
| `git clone ...` | Downloads the repository. |
| `cd qise` | Enters the project directory. |
| `python3.11 -m venv .venv` | Creates a clean Python environment. |
| `source .venv/bin/activate` | Activates that environment. |
| `pip install -e ".[proxy]"` | Installs Qise in editable mode with proxy runtime dependencies. |
| `qise doctor` | Checks Python, Qise import, config, local ports, event log, optional SLM, and detected agents. | -->

To serve Qise tools through MCP, install the separate extra: `pip install -e ".[mcp]"`. Scanning MCP configuration files does not require this extra.

For development and tests:

```bash
pip install -e ".[dev,proxy]"
```

## First Safe CLI Demo

This demo uses temporary directories and does not touch your real Codex config:

```bash
bash ./scripts/demo_mvp.sh
```

The demo runs readiness checks, protects a fake Codex config, blocks a dangerous command, prints the event, and restores the temporary config.

You can also run the preflight scan demo:

```bash
bash ./scripts/demo_scan.sh
```

It scans a safe skill, a dangerous skill, and a dangerous MCP config, then shows the events Qise recorded.

## Manual CLI Walkthrough

After installation, this sequence gives you a quick product loop:

```bash
qise version
qise doctor
qise status
qise agents
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

What these commands mean:

| Command | What it does |
| --- | --- |
| `qise version` | Prints the installed Qise version. |
| `qise doctor` | Runs readiness diagnostics and tells you what is missing or only partially configured. |
| `qise status` | Shows active services, protected agents, detected agents, SLM state, and recent event counts. |
| `qise agents` | Detects supported local agent CLIs/configs, such as Codex, OpenClaw, or Claude Code. |
| `qise scan skill ...` | Scans a skill directory or file before you trust/install it. |
| `qise scan mcp ...` | Scans an MCP JSON/YAML config for risky commands, exposed env vars, injection text, and suspicious callbacks. |
| `qise check bash ...` | Runs one guard pipeline check manually against a tool call. The example should be blocked. |
| `qise events --limit 10` | Shows the most recent local security events in a readable format. |

The `|| true` suffix is used because a block is represented as a non-zero exit code. That is expected for dangerous test inputs.

For machine-readable output:

```bash
qise status --json
qise events --limit 10 --json
qise scan mcp examples/mcp-dangerous.json --json || true
```

## Protect A Real Agent With The CLI

Protection means Qise backs up your agent config, patches the agent's model base URL to point at the local Qise proxy, starts managed Qise services, and records the backup path so you can restore later.

Before protecting a real agent, make sure:

- Your agent already works without Qise.
- Your model provider API key is still available in the environment your agent uses.
- You know the upstream model API base URL if Qise cannot infer it from the agent config.

Protect Codex:

```bash
qise protect codex
qise status
qise events --limit 10
```

If Qise cannot infer the upstream provider:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

Protect OpenCode's selected provider:

```bash
qise protect opencode
# If the upstream cannot be inferred:
qise protect opencode --base-url https://api.example.com/v1
```

Only the selected provider in the detected global JSON/JSONC configuration is changed. Other providers are preserved. Project configuration can override global settings; verify the actual route used by that project.

WorkBuddy currently supports scanning and manual custom-model connection:

```bash
qise scan agent workbuddy
qise protect custom --base-url https://api.example.com/v1
```

Then enter the printed Qise URL in WorkBuddy's custom model settings. `qise protect workbuddy` does not modify its configuration, and built-in model traffic or a manual connection is not automatically verified as protected.

Protect OpenClaw:

```bash
qise protect openclaw
```

Protect Claude Code:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
qise protect claude-code --base-url https://api.anthropic.com
qise status
```

What the Claude Code command does:

| Command | What it does |
| --- | --- |
| `export ANTHROPIC_API_KEY=...` | Keeps your Anthropic key available to Claude Code and the Qise-managed proxy process. |
| `qise protect claude-code --base-url https://api.anthropic.com` | Backs up `~/.claude/settings.json`, sets `env.ANTHROPIC_BASE_URL` to the local Qise proxy, records the original Anthropic upstream, and starts Qise services. |
| `qise status` | Confirms Claude Code is protected and shows the backup path. |

Protect a custom OpenAI-compatible agent:

```bash
qise protect custom --base-url https://api.openai.com/v1
```

For a custom agent, Qise starts the proxy and prints the local proxy URL. Point your agent's base URL to:

```text
http://127.0.0.1:8822/v1
```

Restoring removes Qise's configuration changes while preserving unrelated settings edited afterward where the format permits. If a conflicting edited Qise provider block cannot be safely restored, the command fails without overwriting it; inspect the retained backup. Backups are kept after restore.

`qise stop` restores all configured agents before stopping services. If recovery fails, services keep running so remaining clients retain their connection. You can also restore a connection explicitly before stopping or uninstalling:

```bash
qise restore codex
qise restore all
qise stop
```

## CLI Command Map

| Command | Use it when you want to |
| --- | --- |
| `qise init` | Generate a local `shield.yaml` config file. |
| `qise doctor` | Diagnose local readiness. |
| `qise status` | See service, protection, SLM, agent, and event status. |
| `qise agents` | Detect supported installed agents. |
| `qise protect <agent>` | Back up and route an agent through Qise. |
| `qise restore <agent|all>` | Restore agent config modified by Qise. |
| `qise stop` | Restore configured agents, then stop managed services; keep services running if recovery fails. |
| `qise scan all` | Scan detected agent assets automatically. |
| `qise scan agent <agent>` | Scan one agent's config, skill files, and MCP candidates. |
| `qise scan skill <path>` | Scan a skill directory or file. |
| `qise scan mcp <path>` | Scan an MCP JSON/YAML config. |
| `qise scan agent-config <agent>` | Check whether an installed agent config is routed through Qise and still matches Qise state. |
| `qise check <tool> <json>` | Manually run a guard pipeline check. |
| `qise events` | Read local security events. |
| `qise slm start/status/stop` | Configure or disable the optional local SLM review layer. |
| `qise run --agent <name> -- <cmd>` | Run a command under the Runtime Observer. |
| `qise guards --json` | Read the effective, deduplicated guard policy. |
| `qise guards --set prompt observe --json` | Persist a guard mode shared by the CLI, proxy, bridge, and desktop. |
| `qise context <tool>` | Preview security context text for a tool. |
| `qise proxy start` | Start the local OpenAI-compatible/Anthropic proxy manually. |
| `qise bridge start` | Start the local bridge for guard integration. Desktop policy changes use the CLI. |
| `qise serve --transport stdio` | Start Qise as an MCP server. |
| `qise adapters <name>` | Print SDK integration snippets for supported frameworks. |

## Guard Pipeline

Qise runs checks through three pipelines:

| Pipeline | Direction | Example risks |
| --- | --- | --- |
| Ingress | World to agent | Prompt injection, tool poisoning, context poisoning, supply-chain instructions. |
| Egress | Agent to world | Dangerous shell commands, unsafe file access, risky network calls, exfiltration, resource abuse, tool policy violations. |
| Output | Agent to user/logs | Credential leaks, sensitive output, audit signals. |

The current guard set includes:

| Guard | Main purpose |
| --- | --- |
| `prompt` | Detect direct and indirect prompt injection. |
| `tool_sanity` | Detect poisoned or suspicious tool descriptions. |
| `context` | Detect memory/knowledge-base poisoning patterns. |
| `supply_chain` | Detect risky skills, MCP servers, and supply-chain assets. |
| `command` | Block dangerous shell commands and command injection patterns. |
| `filesystem` | Enforce workspace/path safety and system path protections. |
| `network` | Warn/block suspicious domains, SSRF-like targets, and risky network access. |
| `exfil` | Detect possible data exfiltration. |
| `resource` | Detect resource abuse patterns. |
| `tool_policy` | Enforce configured tool allow/deny policy. |
| `credential` | Detect secrets and credentials in outputs or tool data. |
| `audit` | Record audit-oriented warning signals. |
| `output` | Review final output for sensitive or risky content. |
| `reasoning` | Optional semantic review of model/tool reasoning signals when available. |

Smart Protection defaults `command`, `filesystem`, `network`, `credential`, and `tool_policy` to `enforce`; the remaining guards default to `observe`. Model setup and enforcement mode are independent choices.

Read or change the same effective policy from the desktop or CLI:

```bash
qise guards --json
qise guards --set prompt observe --json
qise guards --set command enforce --json
```

Overrides are saved in `~/.qise/guard-policy.json` (or `QISE_HOME`) and applied by product proxy/bridge checks without a restart. `observe` records warnings, `enforce` permits blocking, and `off` skips the guard. Standalone SDK Shields retain their own configuration.

## Optional Local SLM

Qise starts without a configured SLM. The default installation and first-run scan do not download a model. The optional SLM layer adds semantic review for cases that are hard to catch with simple rules.

Explicitly start local SLM setup when you want it:

```bash
qise slm start
qise slm status
```

By default, Qise uses local Ollama at `http://localhost:11434/v1` with `qwen3:4b`. On first run it can try to install Ollama and pull the model if they are missing.

Use another model:

```bash
qise slm start --model llama3.2:3b
```

Use a custom OpenAI-compatible SLM endpoint:

```bash
qise slm start --base-url http://localhost:8000/v1 --model my-security-model
```

Disable the Qise SLM config:

```bash
qise slm stop
```

If Qise proxy/protection was already running, restore and restart the connection after changing SLM endpoint settings:

```bash
qise restore codex
qise stop
qise protect codex
```

Guard mode changes through `qise guards --set` do not require this restart.

## SDK And Framework Adapters

Qise can also be used inside agent frameworks. This is intended for developers building agents or tools.

Print integration snippets:

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

Example LangGraph snippet:

```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

Example OpenAI Agents SDK snippet:

```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(
    name="my-agent",
    guardrails=[guardrails.input_guardrail, guardrails.output_guardrail],
)
```

Use adapters when you are building an agent and want in-process checks around tools, inputs, outputs, or framework hooks. Use proxy mode when you want zero-code protection for an existing OpenAI-compatible agent or Claude Code.

<!-- ## Integration Modes

| Mode | Code required | Best for |
| --- | --- | --- |
| Desktop app | 0 lines | Regular users who want a visual control panel. |
| Proxy mode | 0 lines | Existing agents that can point model traffic to a local base URL. |
| MCP mode | 0 lines | Agents that can call Qise as an MCP server. |
| SDK mode | 1-5 lines | Developers building agent frameworks or custom tools. | -->

## Project Shape

```text
src/qise/              Python product engine, CLI, proxy, bridge, guards, adapters
src/qise/guards/       Prompt, command, credential, filesystem, network, exfil, and other guards
src/qise/product/      User-facing product flows: protect, restore, scan, status, doctor, events, SLM
src/qise/proxy/        OpenAI-compatible and Anthropic Messages local proxy and streaming support
src/qise/bridge/       Local bridge used by the desktop UI for guard state
src/qise/adapters/     SDK/framework snippets and integrations
src-ui/                React + TypeScript desktop frontend
src-tauri/             Tauri 2 Rust desktop shell and IPC commands
src-proxy/             Rust proxy experiment/runtime components
data/                  Threat patterns, security contexts, prompt examples
docs/                  Deeper installation, architecture, privacy, event, and integration docs
examples/              Safe and dangerous sample skills, MCP configs, and agent examples
tests/                 Python test suite for guards, proxy, CLI, and product flows
```

## Configuration

Qise can run with defaults, but you can create a config file:

```bash
qise init
```

This creates `shield.yaml` in the current directory. Use it to configure proxy settings, model endpoints, data paths, logging, and guard modes.

Common environment variables:

| Variable | Purpose |
| --- | --- |
| `QISE_HOME` | Override Qise state directory. Defaults to `~/.qise`. |
| `QISE_AGENT_HOME` | Test/demo override for agent home/config lookup. |
| `QISE_PROXY_UPSTREAM_URL` | Upstream model API base URL for proxy mode. |
| `QISE_PROXY_UPSTREAM_API_KEY` | Upstream model API key passed to Qise proxy. |
| `OPENAI_API_BASE` | Fallback upstream base URL. |
| `OPENAI_API_KEY` | Common provider API key env used by agents and Qise. |
| `ANTHROPIC_BASE_URL` | Anthropic upstream base URL used by Claude Code or native Anthropic clients. |
| `ANTHROPIC_API_KEY` | Anthropic API key. Qise forwards it as `X-Api-Key` for `/v1/messages`. |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic auth token. Qise forwards it as `Authorization: Bearer ...` for `/v1/messages`. |
| `QISE_SLM_BASE_URL` | Override SLM endpoint. |
| `QISE_SLM_MODEL` | Override SLM model name. |
| `QISE_BINARY` | Desktop app override for the Qise executable. |

## Local Files Qise Creates

By default:

```text
~/.qise/state.json       # current services, protected agents, SLM state
~/.qise/guard-policy.json # persisted guard-mode overrides
~/.qise/events.jsonl     # local security events
~/.qise/backups/         # agent config backups before patching
~/.qise/logs/            # managed proxy/bridge stdout and stderr logs
```

Useful inspection commands:

```bash
qise status
qise events --limit 20
ls ~/.qise/backups
```

## Troubleshooting

`qise doctor` says "Proxy upstream is not configured yet."

This is normal before you protect a real agent. Qise needs an upstream model API only when it is going to forward traffic. Use:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect codex` cannot infer the provider.

Pass the upstream explicitly:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect claude-code` cannot infer the Anthropic upstream.

Pass it explicitly:

```bash
qise protect claude-code --base-url https://api.anthropic.com
```

Qise patched an agent and you want to undo it.

```bash
qise restore all
qise stop
```

The desktop app cannot find Qise.

Make sure the CLI works in the same shell:

```bash
qise version
```

If needed, set:

```bash
export QISE_BINARY=/path/to/qise
```

A scan command exits non-zero.

That usually means Qise found a blocking issue. Re-run with `--json` for structured details or read the latest event:

```bash
qise events --limit 5
```

## Current Limitations

- The macOS and Windows installers in this repository are currently unsigned test builds.
- HTTP proxy coverage includes Chat Completions, Anthropic Messages, and supported Responses text/function/custom-tool flows. WebSocket, upstream-hosted tool execution, and unrecognized API routes are outside the execution gate. Streamed text is audited after delivery; see [protocol boundaries](./docs/integration.md#http-protocol-coverage).
- Healthy service identity and matching configuration do not prove complete agent execution coverage. Project overrides, built-in model paths, and calls that bypass Qise remain outside the proxy.
- Historical benchmark reports use older metric/mode behavior. Use the corrected [evaluation runner](./eval/README.md); detection F1 is not a blocking-success rate.
- Runtime Observer is a user-space wrapper, not OS/kernel-level auditing.
- Local SLM quality and latency depend on the model and server you choose.
- The Windows EXE is produced by a GitHub Actions Windows runner and cannot be installation-tested directly on macOS.

## Learn More

- [Protection behavior and upgrade notes](./docs/protection-upgrade.md)
- [Install](./docs/install.md)
- [Quickstart](./docs/quickstart.md)
- [Architecture](./docs/architecture.md)
- [Guards](./docs/guards.md)
- [Codex integration](./docs/codex.md)
- [OpenClaw integration](./docs/openclaw.md)
- [Claude Code integration](./docs/claude-code.md)
- [Preflight scan](./docs/preflight-scan.md)
- [Events](./docs/events.md)
- [Runtime Observer](./docs/runtime-observer.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Privacy](./docs/privacy.md)

## License

[CC BY-NC-SA 4.0](./LICENSE) - free for personal, academic, and non-commercial use. Commercial use requires separate permission.
