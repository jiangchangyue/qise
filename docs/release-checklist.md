# Qise MVP Release Checklist

Use this checklist before tagging or publicly promoting a release. It keeps the first-week MVP honest: installable, protectable, explainable, restorable.

## 1. Fresh Install Smoke Test

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
qise status
```

Pass criteria:

- `qise doctor` returns `ready` or `ready_with_warnings` with no errors.
- `qise status` shows Services, SLM, Protection, Agents, and Events sections.

## 2. Rule-Only Safety Loop

```bash
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

Pass criteria:

- Safe fixture passes.
- Dangerous Skill/MCP and dangerous command produce BLOCK/WARN events with evidence.
- Qise still works without SLM configured.

## 3. Optional Local SLM Loop

```bash
qise slm start
qise slm status
qise doctor
```

Pass criteria:

- `qise slm status` shows configured `yes`, provider `Ollama`, and verification `ready`.
- If the model is not ready, the error is understandable and `qise slm stop` returns Qise to rule-only mode.

## 4. Agent Protect/Restore Loop

Run at least one real Agent path before promotion.

```bash
qise protect codex
qise status
qise scan agent-config codex
qise restore codex
qise stop
```

For OpenClaw:

```bash
qise protect openclaw
qise status
qise scan agent-config openclaw
qise restore openclaw
qise stop
```

Pass criteria:

- Config backup is created under `~/.qise/backups/...`.
- Agent config points to `http://127.0.0.1:8822/agent/<agent>/v1` while protected.
- Restore returns the original config exactly.

## 5. Proxy Runtime Loop

```bash
qise protect <agent>
# Start and use the protected Agent normally.
qise events --limit 20
qise status
```

Pass criteria:

- Requests flow through Qise proxy.
- Dangerous tool calls are blocked or warned according to guard mode.
- Events include source, stage, decision, evidence, recommendation, and event id.

## 6. Desktop Release

### One-time repository setup

This fork publishes desktop releases to `jiangchangyue/qise` and uses its own updater signing key. The public key in `src-tauri/tauri.conf.json` must match that private key, and the updater endpoint must point to this repository:

```text
https://github.com/jiangchangyue/qise/releases/latest/download/latest.json
```

Keep a secure private-key backup outside the repository and any build artifacts. The following commands use `/secure/private-backup/qise-updater.key` as an example; replace it with the actual protected backup path. Add the exact file contents to the repository secret:

```bash
gh secret set TAURI_SIGNING_PRIVATE_KEY --repo jiangchangyue/qise < /secure/private-backup/qise-updater.key
```

When using the GitHub website on macOS, copy the exact file contents without
printing them in the terminal:

```bash
pbcopy < /secure/private-backup/qise-updater.key
```

Then paste into the secret value field. Do not copy the `%` marker that zsh may
display after `cat` when a file has no trailing newline.

For an unencrypted key, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` may remain unset. For a password-protected key, add its password as that second secret. Never commit or print the private key in logs. Forks do not inherit the upstream repository's secrets.

The desktop release workflow uses the repository's `GITHUB_TOKEN` with `contents: write`; a separate release access token is not required. Enable GitHub Actions for the fork before pushing a release tag.

### Prepare and trigger a stable release

All release-bearing files must use the same semantic version, including the `qise-app` entry in `src-tauri/Cargo.lock`. For Qise 0.2.1:

```bash
python scripts/check_release_version.py --expected 0.2.1
PYTHONPATH=src pytest tests/test_release_version.py tests/test_cli.py tests/test_product_cli.py -q
npm test --prefix src-ui
npm run build --prefix src-ui
cargo test --manifest-path src-tauri/Cargo.toml
git status --short
```

Commit and push the release-ready source, then create the matching tag:

```bash
git push origin main
git tag -a v0.2.1 -m "Qise v0.2.1"
git push origin v0.2.1
```

The tag triggers `Publish Desktop Release`, which builds Windows x64 and macOS Apple Silicon, signs updater artifacts, generates `latest.json`, and creates a draft GitHub Release. Wait for both platform jobs to succeed before publishing.

Before publishing the draft, confirm it contains:

- macOS DMG for first installation.
- macOS updater archive and `.sig`.
- Windows x64 NSIS installer and `.sig`.
- `latest.json` with version `0.2.1`, signed `darwin-aarch64` and `windows-x86_64` entries, and asset URLs pointing to `jiangchangyue/qise`.

Check that each updater artifact verifies against the configured public key. Updater signatures do not provide Apple Developer ID notarization or Windows Authenticode signing; document these installation limitations in the release notes.

Once both platforms' assets have been checked, publish the draft as a stable, non-prerelease Release. The PyPI workflow is restricted to the upstream `WhitzardAgent/qise` repository; this fork publishes desktop releases without publishing a PyPI package. Verify the public updater manifest:

```bash
curl -fsSL https://github.com/jiangchangyue/qise/releases/latest/download/latest.json
```

Users of upstream desktop builds must manually install this fork's 0.2.1 build once to adopt its update channel and signing key. Subsequent updates come from this repository. Test end-to-end automatic updating with the next higher signed version.

## 7. GitHub Hygiene

```bash
git status --short
pytest tests/test_product_cli.py tests/test_ollama_compat.py tests/test_model_router_real.py
ruff check src/qise tests
```

Pass criteria:

- No secrets, local `shield.yaml`, event logs, model caches, or internal planning docs are staged.
- Public docs describe Claude Code native Anthropic `/v1/messages` support only when parser, proxy, streaming, protect, restore, and event evidence tests pass.
- README quickstart, SLM commands, OpenClaw/Codex/Claude Code docs, and release notes are consistent.
