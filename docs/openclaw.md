# OpenClaw Integration

OpenClaw support uses the same local proxy idea as Codex, but JSON config formats vary across installs.

## Commands

```bash
qise doctor
qise protect openclaw
qise status
qise restore openclaw
```

## What Qise Looks For

Qise currently checks these paths:

```text
~/.openclaw/openclaw.json
~/.openclaw/config.json
~/.config/openclaw/config.json
~/.claw/config.json
```

For modern layouts, Qise reads `agents.defaults.model.primary` and rewrites only that provider's `models.providers.<name>.baseUrl` to `http://127.0.0.1:8822/agent/openclaw/v1`. Other providers remain unchanged. It accepts supported OpenAI or Anthropic HTTP protocols; legacy configs with one unambiguous endpoint are also supported. Ambiguous configurations are left unchanged. This follows the [OpenClaw custom provider schema](https://docs.openclaw.ai/gateway/config-tools/custom-providers).

Qise metadata is stored in `~/.qise/state.json`, not added to the OpenClaw config. Switching providers, using fallback models, or overriding endpoints may bypass this selected route; check status after such changes. Full JSON5 syntax is not supported by this config editor.

## Validation

After protect:

```bash
qise scan agent-config openclaw
qise status
```

Because OpenClaw config layouts may differ, inspect the generated backup and patch diff under `~/.qise/backups/openclaw/...` before broad use.
