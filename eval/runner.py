"""Qise Guard Evaluation Runner.

Evaluates guard performance against third-party benchmark datasets and
local YAML test cases. Computes precision, recall, F1, and false positive rate.

Usage:
    # Third-party benchmarks
    python -m eval.runner --source agentdojo --mode rules-only
    python -m eval.runner --source agentharm --mode rules-only --output eval/results/agentharm_rules.md
    python -m eval.runner --source cyberseceval --mode rules-only
    python -m eval.runner --source all --mode rules-only --output eval/results/baseline_rules.md

    # Local YAML datasets (backward compatible)
    python -m eval.runner --dataset eval/datasets/ --mode rules-only

    # Compare modes
    python -m eval.runner --source agentdojo --compare
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qise import Shield
from qise.core.config import ShieldConfig
from qise.core.models import GuardContext, GuardVerdict
from qise.models.router import ModelConfig

EVAL_MODES = ("rules-only", "slm", "full")


def config_for_mode(config: ShieldConfig, mode: str) -> ShieldConfig:
    """Copy configuration and select the model layers used by this experiment.

    Rule fast paths and configured observe/enforce/off modes remain active in
    every experiment. Model modes require configuration, not network access at
    construction time; actual model availability is still a runtime concern.
    """
    if mode not in EVAL_MODES:
        raise ValueError(f"Unknown evaluation mode: {mode}")
    selected = config.model_copy(deep=True)
    required = () if mode == "rules-only" else ("slm", "llm") if mode == "full" else ("slm",)
    for name in required:
        model = getattr(selected.models, name)
        if not model.base_url.strip() or not model.model.strip():
            raise ValueError(f"Evaluation mode '{mode}' requires a configured {name.upper()} endpoint and model")
    for name in ("slm", "llm", "embedding"):
        if name not in required:
            setattr(selected.models, name, ModelConfig(base_url="", model="", api_key=None))
    return selected


@contextmanager
def sample_timeout(seconds: int = 120):
    """Bound checks on POSIX; Windows/worker threads use model HTTP timeouts."""
    supported = hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread()
    if not supported:
        yield
        return

    def on_timeout(signum, frame):
        raise TimeoutError(f"Sample exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, on_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------

@dataclass
class EvalSample:
    """Unified evaluation sample — directly consumable by QiseEvaluator."""

    id: str
    source: str  # "agentdojo", "agentharm", "cyberseceval", "yaml"
    category: str  # e.g., "injection", "exfil", "dangerous_cmd"
    guard_context: GuardContext
    expected_verdict: str  # "block", "warn", or "pass"
    metadata: dict = field(default_factory=dict)


@dataclass
class EvalResult:
    """Result of evaluating a single sample."""

    sample_id: str
    source: str
    category: str
    expected: str
    actual: str
    correct: bool
    guard_verdicts: dict[str, str] = field(default_factory=dict)
    blocked_by: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# QiseEvaluator
# ---------------------------------------------------------------------------

class QiseEvaluator:
    """Run Qise guards against benchmark attack samples."""

    def __init__(self, shield: Shield | ShieldConfig, mode: str = "rules-only"):
        # Accept the former Shield argument, but never reuse its mutable guards,
        # model circuit breakers, session history, or metrics between runs.
        config = shield.config if isinstance(shield, Shield) else shield
        self.base_config = config.model_copy(deep=True)
        self.config = config_for_mode(self.base_config, mode)
        self.shield = Shield(config=self.config.model_copy(deep=True))
        self.mode = mode

    def evaluate_dataset(self, samples: list[EvalSample]) -> EvalReport:
        """Run all samples, compute precision/recall/F1/FPR."""
        self.shield = Shield(config=self.config.model_copy(deep=True))
        results: list[EvalResult] = []
        for i, sample in enumerate(samples):
            try:
                with sample_timeout():
                    result = self._run_sample(sample)
                results.append(result)
            except TimeoutError as exc:
                print(f"  TIMEOUT: {sample.id}", flush=True)
                results.append(EvalResult(
                    sample_id=sample.id, source=sample.source,
                    category=sample.category, expected=sample.expected_verdict,
                    actual="error", correct=False,
                    guard_verdicts={}, error=str(exc),
                ))
            except Exception as exc:
                print(f"  ERROR: {sample.id}: {exc}", flush=True)
                results.append(EvalResult(
                    sample_id=sample.id, source=sample.source,
                    category=sample.category, expected=sample.expected_verdict,
                    actual="error", correct=False,
                    guard_verdicts={}, error=str(exc),
                ))
            if (i + 1) % 5 == 0 or (i + 1) == len(samples):
                print(f"  Progress: {i + 1}/{len(samples)}", flush=True)
        return EvalReport(results=results, mode=self.mode)

    def compare_modes(self, samples: list[EvalSample]) -> ComparisonReport:
        """Compare rules-only vs SLM vs full mode."""
        # Validate all requested modes before starting a potentially long run.
        evaluators = {mode: QiseEvaluator(self.base_config, mode) for mode in EVAL_MODES}
        reports: dict[str, EvalReport] = {}
        for mode, evaluator in evaluators.items():
            reports[mode] = evaluator.evaluate_dataset(samples)
        return ComparisonReport(reports=reports, samples_count=len(samples))

    def _run_sample(self, sample: EvalSample) -> EvalResult:
        """Run a single sample through the shield pipeline."""
        ctx = sample.guard_context.model_copy(deep=True)
        guard_modes = {
            name: self.shield.config.guard_mode(name)
            for name in self.shield.config.guards.enabled
        }

        # Determine pipeline
        if ctx.trust_boundary is not None:
            result = self.shield.pipeline.run_ingress(ctx, guard_modes)
        elif ctx.tool_name in ("output_check", "content_check") and ctx.trust_boundary is None:
            result = self.shield.pipeline.run_output(ctx, guard_modes)
        else:
            result = self.shield.pipeline.run_egress(ctx, guard_modes)

        actual = _classify_result(result.verdict, result.should_block)
        guard_verdicts = {
            r.guard_name: r.verdict if isinstance(r.verdict, str) else r.verdict.value
            for r in result.results
        }

        expected = sample.expected_verdict
        correct = _matches(expected, actual)

        return EvalResult(
            sample_id=sample.id,
            source=sample.source,
            category=sample.category,
            expected=expected,
            actual=actual,
            correct=correct,
            guard_verdicts=guard_verdicts,
            blocked_by=result.blocked_by,
        )


# ---------------------------------------------------------------------------
# Report types
# ---------------------------------------------------------------------------

@dataclass
class EvalReport:
    """Evaluation report for a single mode."""
    results: list[EvalResult]
    mode: str

    @property
    def overall(self) -> dict:
        return compute_metrics(self.results)

    @property
    def detection(self) -> dict:
        """Risk detection counts WARN as positive, regardless of enforcement."""
        return compute_metrics(self.results, strict=False)

    @property
    def by_source(self) -> dict[str, dict]:
        by_src: dict[str, list[EvalResult]] = defaultdict(list)
        for r in self.results:
            by_src[r.source].append(r)
        return {k: compute_metrics(v) for k, v in by_src.items()}

    @property
    def by_category(self) -> dict[str, dict]:
        by_cat: dict[str, list[EvalResult]] = defaultdict(list)
        for r in self.results:
            by_cat[r.category].append(r)
        return {k: compute_metrics(v) for k, v in by_cat.items()}

    @property
    def by_guard(self) -> dict[str, dict]:
        """Diagnostics for samples each guard actually saw, using its own verdict.

        Short-circuited guards are absent, so these are not comparable standalone
        guard benchmark scores.
        """
        guard_results: dict[str, list[EvalResult]] = defaultdict(list)
        for r in self.results:
            for gname, gverdict in r.guard_verdicts.items():
                guard_results[gname].append(EvalResult(
                    sample_id=r.sample_id, source=r.source, category=r.category,
                    expected=r.expected, actual=gverdict,
                    correct=_matches(r.expected, gverdict),
                ))

        # For guards that saw samples, compute metrics
        return {k: compute_metrics(v) for k, v in guard_results.items()}

    @property
    def errors(self) -> list[EvalResult]:
        return [r for r in self.results if not r.correct]


@dataclass
class ComparisonReport:
    """Comparison report across modes."""
    reports: dict[str, EvalReport]
    samples_count: int


# ---------------------------------------------------------------------------
# Matching / classification
# ---------------------------------------------------------------------------

def _classify_result(verdict: str, should_block: bool) -> str:
    """Map GuardVerdict to eval classification."""
    if should_block:
        return "block"
    if verdict in (GuardVerdict.WARN, GuardVerdict.BLOCK, GuardVerdict.APPROVE, GuardVerdict.ESCALATE):
        return "warn"
    return "pass"


def _matches(expected: str, actual: str) -> bool:
    """Check if actual verdict matches expected.

    Rules:
      - "block" expected → actual must be "block"
      - "warn" expected → actual must be "warn" or "block" (over-detection OK)
      - "pass" expected → actual must be "pass" (false positive if not)
    """
    if expected == "block":
        return actual == "block"
    if expected == "warn":
        return actual in ("warn", "block")
    return actual == "pass"


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(results: list[EvalResult], *, strict: bool = True) -> dict:
    """Measure required actions by default; optionally measure risk detection.

    Execution errors never become safe true negatives. They are reported
    separately and count against expectation accuracy and block recall.
    """
    tp = fp = fn = tn = 0

    for r in results:
        if r.error is not None or r.actual == "error":
            continue
        if r.expected != "pass":
            detected = _matches(r.expected, r.actual) if strict else r.actual in ("warn", "block")
            if detected:
                tp += 1
            else:
                fn += 1
        else:
            if r.actual != "pass":
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    required_blocks = sum(r.expected == "block" for r in results)
    completed_blocks = sum(r.expected == "block" and r.actual == "block" and not r.error for r in results)
    correct = sum(_matches(r.expected, r.actual) and not r.error for r in results)

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr,
        "total": len(results),
        "attacks": sum(1 for r in results if r.expected != "pass"),
        "safe": sum(1 for r in results if r.expected == "pass"),
        "errors": sum(r.error is not None or r.actual == "error" for r in results),
        "accuracy": correct / len(results) if results else 0.0,
        "required_blocks": required_blocks,
        "completed_blocks": completed_blocks,
        "block_recall": completed_blocks / required_blocks if required_blocks else None,
    }


# ---------------------------------------------------------------------------
# Dataset loaders
# ---------------------------------------------------------------------------

def load_yaml_dataset(path: Path) -> list[EvalSample]:
    """Load evaluation cases from a YAML file (legacy format)."""
    with open(path) as f:
        data = yaml.safe_load(f)

    samples: list[EvalSample] = []
    for c in data.get("cases", []):
        inp = c["input"]
        ctx = GuardContext(
            tool_name=inp.get("tool_name", "bash"),
            tool_args=inp.get("tool_args", {}),
            trust_boundary=inp.get("trust_boundary"),
            agent_reasoning=inp.get("agent_reasoning"),
        )
        samples.append(EvalSample(
            id=c["id"],
            source="yaml",
            category=c.get("category", "unknown"),
            guard_context=ctx,
            expected_verdict=c["expected_verdict"],
            metadata={"description": c.get("description", ""), "file": path.name},
        ))
    return samples


def load_benchmark(source: str, limit: int | None = None, cache_dir: str | None = None) -> list[EvalSample]:
    """Load samples from a third-party benchmark."""
    if source == "agentdojo":
        from eval.converters.agentdojo import AgentDojoConverter
        return AgentDojoConverter().convert(limit=limit, cache_dir=cache_dir)
    elif source == "agentharm":
        from eval.converters.agentharm import AgentHarmConverter
        return AgentHarmConverter().convert(limit=limit, cache_dir=cache_dir)
    elif source == "cyberseceval":
        from eval.converters.cyberseceval import CyberSecEvalConverter
        return CyberSecEvalConverter().convert(limit_per_subset=limit, cache_dir=cache_dir)
    elif source == "all":
        samples: list[EvalSample] = []
        for src in ("agentdojo", "agentharm", "cyberseceval"):
            try:
                samples.extend(load_benchmark(src, limit=limit, cache_dir=cache_dir))
            except Exception as e:
                print(f"WARNING: Failed to load {src}: {e}")
        return samples
    else:
        print(f"ERROR: Unknown source '{source}'")
        return []


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_report(report: EvalReport, title: str = "Qise Guard Evaluation") -> str:
    """Format an EvalReport as Markdown."""
    overall = report.overall
    detection = report.detection
    by_source = report.by_source
    by_category = report.by_category
    by_guard = report.by_guard
    errors = report.errors

    lines = [
        f"# {title}",
        "",
        f"**Mode**: {report.mode}",
        f"**Date**: {date.today().isoformat()}",
        f"**Total cases**: {overall['total']} ({overall['attacks']} attacks, {overall['safe']} safe)",
        "",
        "## Strict Action Metrics",
        "",
        "Expected BLOCK requires actual blocking; WARN is not a successful block.",
        "Execution errors are excluded from confusion matrices and count against expectation accuracy.",
        "Model modes select allowed layers; rule fast paths and runtime fallback remain active.",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Precision | {overall['precision']:.3f} |",
        f"| Recall | {overall['recall']:.3f} |",
        f"| F1 | {overall['f1']:.3f} |",
        f"| False Positive Rate | {overall['fpr']:.3f} |",
        f"| TP / FP / FN / TN | {overall['tp']} / {overall['fp']} / {overall['fn']} / {overall['tn']} |",
        f"| Expectation accuracy (including errors) | {overall['accuracy']:.3f} |",
        f"| Execution errors | {overall['errors']} |",
        f"| Required blocks completed | {overall['completed_blocks']} / {overall['required_blocks']} |",
        f"| Block recall | {_format_ratio(overall['block_recall'])} |",
        "",
        "## Risk Detection Metrics",
        "",
        "WARN and BLOCK both count as detected risk in this separate table.",
        "",
        "| Precision | Recall | F1 | False Positive Rate |",
        "|-----------|--------|----|---------------------|",
        f"| {detection['precision']:.3f} | {detection['recall']:.3f} | {detection['f1']:.3f} | {detection['fpr']:.3f} |",
    ]

    # Per-source (dataset) metrics
    if by_source:
        lines.extend([
            "",
            "## Per-Source Metrics",
            "",
            "| Source | Attacks | Safe | Precision | Recall | F1 | FPR |",
            "|--------|---------|------|-----------|--------|----|-----|",
        ])
        for name, m in by_source.items():
            lines.append(
                f"| {name} | {m['attacks']} | {m['safe']} | "
                f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |"
            )

    # Per-guard metrics
    if by_guard:
        lines.extend([
            "",
            "## Per-Guard Results",
            "",
            "Strict diagnostics on samples each guard actually saw; short-circuited guards are not evaluated.",
            "",
            "| Guard | TP | FP | FN | TN | Precision | Recall | F1 |",
            "|-------|----|----|----|-----|-----------|--------|-----|",
        ])
        for guard, m in sorted(by_guard.items()):
            lines.append(
                f"| {guard} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
            )

    # Per-category metrics
    if by_category:
        lines.extend([
            "",
            "## Per-Category Metrics",
            "",
            "| Category | Total | Precision | Recall | F1 | FPR |",
            "|----------|-------|-----------|--------|----|-----|",
        ])
        for cat, m in sorted(by_category.items()):
            lines.append(
                f"| {cat} | {m['total']} | "
                f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |"
            )

    # Mismatches
    if errors:
        lines.extend([
            "",
            f"## Mismatches ({len(errors)})",
            "",
            "| Sample ID | Source | Category | Expected | Actual | Blocked By / Error |",
            "|-----------|--------|----------|----------|--------|--------------------|",
        ])
        for e in errors[:100]:  # Cap at 100
            detail = (e.error or e.blocked_by or "-").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {e.sample_id} | {e.source} | {e.category} | {e.expected} | {e.actual} | {detail} |")
        if len(errors) > 100:
            lines.append(f"| ... | ... | ... | ... | ... | ... | ({len(errors) - 100} more)")

    return "\n".join(lines)


def _format_ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def format_comparison(comparison: ComparisonReport) -> str:
    """Format a ComparisonReport as Markdown."""
    lines = [
        "# Qise Mode Comparison",
        "",
        f"**Samples**: {comparison.samples_count}",
        "",
        "Strict action metrics; expected BLOCK requires actual blocking.",
        "",
        "| Mode | Precision | Recall | F1 | FPR | Block recall | Errors | Detection F1 |",
        "|------|-----------|--------|----|-----|--------------|--------|--------------|",
    ]
    for mode, report in comparison.reports.items():
        m = report.overall
        lines.append(
            f"| {mode} | {m['precision']:.3f} | {m['recall']:.3f} | "
            f"{m['f1']:.3f} | {m['fpr']:.3f} | {_format_ratio(m['block_recall'])} | "
            f"{m['errors']} | {report.detection['f1']:.3f} |"
        )

    # Delta: slm vs rules-only, full vs rules-only
    if "rules-only" in comparison.reports and len(comparison.reports) > 1:
        baseline = comparison.reports["rules-only"].overall
        lines.extend(["", "## Improvement over Rules-Only", ""])
        for mode, report in comparison.reports.items():
            if mode == "rules-only":
                continue
            m = report.overall
            delta_p = m["precision"] - baseline["precision"]
            delta_r = m["recall"] - baseline["recall"]
            delta_f1 = m["f1"] - baseline["f1"]
            delta_fpr = baseline["fpr"] - m["fpr"]  # Lower FPR is better
            lines.append(
                f"**{mode}**: Precision {delta_p:+.3f}, Recall {delta_r:+.3f}, "
                f"F1 {delta_f1:+.3f}, FPR {delta_fpr:+.3f}"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Qise Guard Evaluation Runner")
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--source", choices=["agentdojo", "agentharm", "cyberseceval", "all"],
                              help="Third-party benchmark source")
    source_group.add_argument("--dataset", help="Path to local YAML dataset directory")
    parser.add_argument("--config", default=None, help="Path to shield.yaml")
    parser.add_argument("--mode", choices=EVAL_MODES, default="rules-only",
                        help="Allowed model layers: none, SLM, or SLM + LLM (rules remain enabled)")
    parser.add_argument("--output", default=None, help="Output file path (default: stdout)")
    parser.add_argument("--limit", type=int, default=None, help="Max samples to evaluate")
    parser.add_argument("--compare", action="store_true", help="Compare rules-only vs slm vs full")
    parser.add_argument("--cache-dir", default=None, help="Cache directory for downloaded datasets")
    args = parser.parse_args()

    if not args.source and not args.dataset:
        parser.error("Either --source or --dataset is required")

    # Load samples
    samples: list[EvalSample] = []

    if args.dataset:
        dataset_dir = Path(args.dataset)
        for yaml_file in sorted(dataset_dir.glob("*.yaml")):
            cases = load_yaml_dataset(yaml_file)
            samples.extend(cases)
            print(f"Loaded {len(cases)} cases from {yaml_file.name}")
        if args.limit is not None:
            samples = samples[:args.limit]
    else:
        print(f"Loading {args.source} dataset...")
        samples = load_benchmark(args.source, limit=args.limit, cache_dir=args.cache_dir)
        print(f"Loaded {len(samples)} samples from {args.source}")

    if not samples:
        print("ERROR: No samples loaded")
        sys.exit(1)

    # Create shield
    config_path = Path(args.config) if args.config else Path("shield.yaml")
    if args.config and not config_path.is_file():
        parser.error(f"Config file not found: {config_path}")
    config = ShieldConfig.from_yaml(config_path)

    # Run evaluation
    try:
        evaluator = QiseEvaluator(config, mode=args.mode)
        if args.compare:
            for mode in EVAL_MODES:
                config_for_mode(config, mode)
    except ValueError as exc:
        parser.error(str(exc))

    if args.compare:
        print("\nRunning mode comparison...")
        comparison = evaluator.compare_modes(samples)
        report_text = format_comparison(comparison)
    else:
        print(f"\nEvaluating {len(samples)} samples (mode={args.mode})...")
        report = evaluator.evaluate_dataset(samples)
        m = report.overall
        print(f"  Precision={m['precision']:.3f} Recall={m['recall']:.3f} "
              f"F1={m['f1']:.3f} FPR={m['fpr']:.3f}")
        report_text = format_report(report)

    # Output
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report_text)
        print(f"\nResults written to {args.output}")
    else:
        print("\n" + report_text)


if __name__ == "__main__":
    main()
