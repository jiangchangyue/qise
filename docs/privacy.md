# Privacy

Qise MVP is local-first.

## Local Files

Default local state:

```text
~/.qise/state.json
~/.qise/guard-policy.json
~/.qise/events.jsonl
~/.qise/backups/
~/.qise/logs/
```

You can redirect this for testing:

```bash
export QISE_HOME=/tmp/qise-demo
```

## What Events Store

Events store compact evidence snippets such as:

- blocked command snippets
- scan finding paths
- rule ids
- short recommendations

Events should not become a copy of full model traffic. Proxy and bridge event writers intentionally summarize guard results.


## Local SLM Data Flow

No SLM is configured or started by default. Explicitly running `qise slm start` selects a local Ollama endpoint (`http://localhost:11434/v1`) and the `qwen3:4b` model, and may install Ollama or download the model. In that mode, semantic review prompts are sent to the local model server on your machine, not to a Qise cloud service. The normal agent traffic still goes to the model provider you selected.

Advanced users may point Qise at a custom OpenAI-compatible endpoint with `qise slm start --base-url ... --model ...`. In that case, reviewed snippets are sent to the endpoint you configured, so treat that endpoint as part of your trust boundary.

## Backups

`qise protect` stores full agent config backups so restore can work. Backups can contain inline API keys or other secrets from the original config. Treat `~/.qise/backups/` as sensitive and keep it until recovery is complete. Managed service command metadata does not embed upstream keys.

## Removing Local Data

```bash
qise restore all
qise stop
rm -rf ~/.qise
```
