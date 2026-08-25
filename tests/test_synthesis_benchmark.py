"""
Automated regression test for SpecGuard-AA Stage 3 Property Synthesis Benchmark (RQ2).
Asserts that Full SpecGuard-AA achieves >= 40% Gold Recall and 100% Whitelist Compliance.
"""

import json
from pathlib import Path
import pytest

from benchmark.stage3_synthesis.eval_synthesis import run_evaluation

ROOT_DIR = Path(__file__).resolve().parent.parent
EVAL_MARKDOWN_PATH = ROOT_DIR / "benchmark" / "stage3_synthesis" / "SYNTHESIS_EVAL_RESULTS.md"


def test_stage3_synthesis_benchmark():
    """Assert Stage 3 Synthesis benchmark metrics against RQ2 target thresholds."""
    ablation_summary, per_contract = run_evaluation()

    full_specguard = ablation_summary["full_specguard"]
    tot_synth = full_specguard["total_synthesized"]
    tot_gold = full_specguard["total_gold_count"]

    whitelist_rate = (full_specguard["whitelist_compliant"] / float(tot_synth) * 100.0) if tot_synth else 0.0
    citation_rate = (full_specguard["citation_valid"] / float(tot_synth) * 100.0) if tot_synth else 0.0
    gold_recall = (full_specguard["gold_matched"] / float(tot_gold) * 100.0) if tot_gold else 0.0

    # Assert Whitelist Compliance = 100%
    assert whitelist_rate == 100.0, f"Expected 100% Whitelist Compliance, got {whitelist_rate}%"

    # Assert Citation Accuracy = 100%
    assert citation_rate == 100.0, f"Expected 100% Citation Accuracy, got {citation_rate}%"

    # Assert Gold Invariant Recall >= 40.0%
    assert gold_recall >= 40.0, f"Expected Full SpecGuard-AA Gold Recall >= 40.0%, got {gold_recall}%"

    # Assert Full SpecGuard out-performs Zero-Shot baseline
    zero_shot_recall = (ablation_summary["zero_shot"]["gold_matched"] / float(tot_gold) * 100.0)
    assert gold_recall > zero_shot_recall, f"Full SpecGuard ({gold_recall}%) did not outperform Zero-Shot ({zero_shot_recall}%)"

    # Assert Markdown report exists
    assert EVAL_MARKDOWN_PATH.exists(), f"{EVAL_MARKDOWN_PATH} was not generated!"
