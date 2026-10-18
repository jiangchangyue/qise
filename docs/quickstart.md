# Quickstart

Start with a safety check. Smart Protection can then connect a supported agent to Qise's local HTTP proxy. No SLM, Ollama installation, model download, or GPU is required for this flow.

## Install

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell. See [Install](install.md) for desktop packages and optional dependencies.

## Check Before Connecting

```bash
qise doctor
qise agents --json
qise scan all
qise guards --json
qise events --limit 10
```

The desktop homepage's **Safety Check** runs the same asset scan. A scan inspects supported local assets; it does not prove that an agent's model traffic is routed through Qise.

To try a disposable demo on macOS/Linux:

```bash
bash ./scripts/demo_mvp.sh
```

The demo uses temporary `QISE_HOME` and `QISE_AGENT_HOME` directories instead of your real agent configuration.

## Connect a Supported Agent

Choose the agent you actually use:

```bash
qise protect codex
# Alternatives: qise protect opencode / openclaw / claude-code
qise status --json
```

Qise backs up the selected config before changing its endpoint. OpenCode and OpenClaw use the selected model provider; other providers are left alone. If the upstream cannot be inferred, supply the model API the agent normally uses:

```bash
qise protect opencode --base-url https://api.example.com/v1
```

Check the returned agent status. `configured` means a Qise connection can be restored. `protected` requires the managed services to be healthy and the selected config route to match. A running proxy by itself is not proof of protection; project config overrides or a different client transport may still bypass it.

WorkBuddy supports scans and manual connection, not automatic takeover:

```bash
qise scan agent workbuddy
qise protect custom --base-url https://api.example.com/v1
```

For manual connection, set the agent's supported HTTP API base URL to the local URL printed by Qise. Qise does not automatically verify this manual route. See [protocol coverage](integration.md#http-protocol-coverage).

## Review Rules and Events

Smart Protection uses `enforce` for default command, filesystem, network, credential, and tool-policy rules. Other guards default to `observe`; a warning is not a block. Change a guard only after reviewing its behavior:

```bash
qise guards --json
qise guards --set prompt observe --json
qise events --limit 10 --json
```

Mode changes are saved locally and read by product proxy/Bridge checks without restarting. `info` events describe precautionary guidance or degraded detection; `warn` and `block` report findings.

## Restore Before Stopping

```bash
qise restore codex
# Or: qise restore all
qise stop
```

`qise stop` also restores all configured agents before stopping managed services. If a restore fails, it keeps the services running to avoid breaking the remaining connection. Restore removes Qise's changes while preserving unrelated edits where possible. A conflicting change is reported without overwriting it; the backup remains available.

## Optional Enhanced Detection

Only enable a model if you want semantic review:

```bash
qise slm start --base-url http://localhost:8000/v1 --model my-security-model
qise slm status
qise slm stop
```

An explicit `qise slm start` with no options selects Ollama and `qwen3:4b`, and may install Ollama or download the model. After changing a model endpoint while services are running, restore agent connections, stop services, and connect again. Model review does not automatically change guard modes.

See [protection behavior and upgrade notes](protection-upgrade.md) for status, recovery, protocol, and evaluation boundaries.
