# SPDX-License-Identifier: MIT
"""
Regression Test Suite for Stage 1 Fact Extraction Benchmark (Part 4).
Ensures role accuracy and dataflow recall do not regress below established floors.
"""

import os
import pytest
from benchmark.stage1_fact_extraction.eval_extraction import evaluate_benchmark


def test_extraction_benchmark_metrics():
    res = evaluate_benchmark("benchmark/stage1_fact_extraction")
    summary = res["summary"]

    # Role Accuracy Floor: >= 85.0%
    assert summary["role_accuracy"] >= 0.85, f"Role accuracy regressed below floor: {summary['role_accuracy']*100:.1f}%"

    # Function Recall Floor: >= 85.0%
    assert summary["function_recall"] >= 0.85, f"Function recall regressed below floor: {summary['function_recall']*100:.1f}%"

    # Dataflow Precision Floor: >= 85.0%
    assert summary["dataflow_read_precision"] >= 0.85, f"Dataflow precision regressed below floor: {summary['dataflow_read_precision']*100:.1f}%"

    # Dataflow Recall Floor: >= 45.0%
    assert summary["dataflow_read_recall"] >= 0.45, f"Dataflow recall regressed below floor: {summary['dataflow_read_recall']*100:.1f}%"
