# QiseGuard-SLM Training Data Preparation

Training data pipeline for QiseGuard-SLM — a dedicated security classification model for AI agent runtime protection.

This directory currently prepares data and a proposed training configuration; it
does not include a training entry point or a validated model release. Schema
validation is not a measure of semantic diversity: the checked-in synthetic files
contain 2,407 examples, including 1,124 repeated user prompts within files (46.7%).
The validator reports these repeats separately from schema errors. Before training,
deduplicate examples and split by source/attack template to keep related variants
out of both training and evaluation; the current converter only exports training
files. A random validation split alone does not establish held-out attack coverage.

## Directory Structure

```
model_training/
├── README.md              # This file
├── datasets/
│   ├── raw/               # Downloaded public datasets (original format)
│   ├── synthetic/         # Synthetically generated data
│   └── processed/         # Converted to QiseGuard training format
├── scripts/
│   ├── download.py        # Download public datasets from HF/GitHub
│   ├── convert.py         # Convert datasets to unified training format
│   ├── synthesize.py      # Generate synthetic data for gap categories
│   ├── validate.py        # Validate training data quality & format
│   └── analyze_coverage.py # Analyze coverage across 10 tasks
├── configs/
│   └── training_config.yaml # LoRA training configuration
└── docs/
    └── dataset_catalog.md  # Catalog of all available datasets
```

## 10 Classification Tasks

| # | Task | Guard | Verdicts | Key Risk Sources |
|---|------|-------|----------|-----------------|
| 1 | Injection Detection | PromptGuard | safe/suspicious/malicious | indirect_injection, context_poisoning, injection_compliance |
| 2 | Command Safety | CommandGuard | safe/suspicious/malicious | command_injection, privilege_escalation, obfuscation |
| 3 | Exfiltration Detection | ExfilGuard | safe/suspicious/malicious | credential_exfil, data_exfil, dns_exfil, covert_channel |
| 4 | Reasoning Safety | ReasoningGuard | safe/concerned/alarmed | exfil_intent, bypass_intent, privilege_escalation, injection_compliance, evasion_planning |
| 5 | Context Poisoning | ContextGuard | safe/suspicious/malicious | memory_poison, kb_poison |
| 6 | Tool Poisoning | ToolSanityGuard | safe/suspicious/malicious | tool_poison, tool_shadow |
| 7 | Supply Chain | SupplyChainGuard | safe/suspicious/malicious | supply_chain |
| 8 | Resource Abuse | ResourceGuard | safe/suspicious/malicious | infinite_loop, behavioral_anomaly, resource_exhaustion |
| 9 | Output Leakage | OutputGuard | safe/suspicious/malicious | kb_leak, pii_exposure, credential_leak |
| 10 | Attack Chain | AuditGuard | safe/suspicious/malicious | attack_chain, correlated_events |

## Unified Training Format

All training data uses the instruction-following chat format:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are a security classifier. Analyze the input and return JSON with: verdict (safe/suspicious/malicious), confidence (0.0-1.0), risk_source (from enum), reasoning (1-2 sentences). Output ONLY valid JSON, no markdown."
    },
    {
      "role": "user",
      "content": "[guard-specific prompt template rendered with context]"
    },
    {
      "role": "assistant",
      "content": "{\"verdict\": \"malicious\", \"confidence\": 0.95, \"risk_source\": \"indirect_injection\", \"reasoning\": \"...\"}"
    }
  ]
}
```

## Quick Start

```bash
# 1. Download public datasets (13 HF + 14 GitHub + 4 URL)
python scripts/download.py --all

# 2. Analyze coverage gaps
python scripts/analyze_coverage.py

# 3. Generate synthetic data for gap tasks (4, 8 are CRITICAL)
python scripts/synthesize.py --all-gaps

# 4. Convert all data to training format
python scripts/convert.py --all --include-synthetic

# 5. Validate
python scripts/validate.py datasets/processed/
```

## Coverage Status

| Task | Coverage | Best Sources |
|------|----------|-------------|
| 1. Injection | EXCELLENT (~130K attack + 85K safe) | HF 55K+70K, AgentDojo 14K |
| 2. Command | GOOD (~1.8K attack + 1.9K safe) | CyberSecEval, AgentTrust |
| 3. Exfiltration | GOOD→MODERATE (~11K attack) | HF 55K (DATA_EXFILTRATION label), AgentShield |
| 4. Reasoning | CRITICAL (~10 only) | **Needs synthetic generation** |
| 5. Context Poisoning | MODERATE (~350 attack + 100 safe) | AgentPoison, MINJA, ClawSafety |
| 6. Tool Poisoning | STRONG attacks (~36K), LOW safe | AgentDefense-Bench 35K, MCPTox |
| 7. Supply Chain | MODERATE (~70 attack + 443 safe) | OWASP Agentic, AgentDefense-Bench |
| 8. Resource Abuse | CRITICAL (0 public data) | **Needs synthetic generation** |
| 9. Output Leakage | EXCELLENT PII (~407K), needs KB leak | HF PII datasets (156K+41K+209K) |
| 10. Attack Chain | MODERATE (~4.3K attack + 3.2K safe) | AgentTrust RiskChain, Multi-turn Jailbreak |

**2 tasks remain CRITICAL**: Task 4 (Reasoning) and Task 8 (Resource Abuse) — no public data exists.
