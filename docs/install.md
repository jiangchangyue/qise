# Install

## Requirements

- Python 3.11+
- macOS or Linux shell for the shell-based demo scripts; Python CLI commands are also available on Windows
- An existing supported agent install for automatic connection; scans and local checks can run independently
- No Ollama, model download, GPU, or MCP server package required for the normal rule-based flow

## Desktop Install

Download the available desktop installer from:

https://github.com/WhitzardAgent/qise/releases/latest

Supported desktop packages:

- Windows x64 NSIS installer.
- macOS Apple Silicon DMG.

This Qise 0.2.0 build is the first updater-enabled build. Users on an earlier 0.2.0 build must install it manually once because automatic updates require a higher version number. Later releases check after startup. Installation is deferred when status is unknown or an agent still has a Qise connection configured, including when services are stopped.

## Source Install

Recommended before the first PyPI release:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

On Windows PowerShell, activate the virtual environment with `.venv\Scripts\Activate.ps1` instead of `source`. The base package supports scans and rules; the `proxy` extra adds the config watcher. Neither path downloads a model.

Only users serving Qise's MCP tools need the optional server dependency:

```bash
pip install -e ".[mcp]"
qise serve --transport stdio
```

Scanning MCP configuration files does not require this extra. See [Integration](integration.md) for manual MCP registration and HTTP protocol coverage.

For development and tests:

```bash
pip install -e ".[dev,proxy]"
pytest tests
```

## pipx After Release

Once Qise is published to PyPI, the intended command is:

```bash
pipx install qise
```

Until then, use the source install above. A Git-based pipx install may work, but source install is easier to inspect and debug during the MVP phase.

## Verify

```bash
qise version
qise doctor
qise guards --json
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 5
```

## Uninstall Source Install

Restore connected agents before stopping or uninstalling, so they do not keep pointing at a stopped proxy. If restore reports a conflict, resolve it using the retained config and backup before deleting local data.

```bash
qise restore all
qise stop
pip uninstall qise
```

Qise local runtime data remains under `~/.qise/` unless you remove it manually.
