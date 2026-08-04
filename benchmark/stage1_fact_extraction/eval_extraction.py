# SPDX-License-Identifier: MIT
"""
Stage 1 Fact Extraction Evaluation Script for SpecGuard-AA.
Evaluates role detection, function extraction, state tagging, and dataflow precision/recall against ground_truth.json.
"""

import os
import json
import sys
from typing import Dict, Any, List, Set, Tuple

# Reconfigure stdout for UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath("."))

from specguard.extractor import extract_facts


def evaluate_benchmark(benchmark_dir: str = "benchmark/stage1_fact_extraction") -> Dict[str, Any]:
    ground_truth_path = os.path.join(benchmark_dir, "ground_truth.json")
    contracts_dir = os.path.join(benchmark_dir, "contracts")

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt = json.load(f)

    contract_results = []
    
    # Global Metric Counters
    role_tp, role_fp, role_fn = 0, 0, 0
    role_correct_contracts = 0

    func_tp, func_fp, func_fn = 0, 0, 0
    tag_tp, tag_fp, tag_fn = 0, 0, 0
    
    df_tp, df_fp, df_fn = 0, 0, 0

    total_contracts = len(gt["contracts"])

    for file_name, spec in gt["contracts"].items():
        file_path = os.path.join(contracts_dir, file_name)
        if not os.path.exists(file_path):
            print(f"[-] Warning: Contract file {file_path} not found!")
            continue

        facts = extract_facts(file_path)

        # 1. Role Evaluation
        detected_roles = set([r.value for r in facts.roles])
        expected_roles = set(spec.get("expected_roles", []))
        
        c_role_tp = len(detected_roles & expected_roles)
        c_role_fp = len(detected_roles - expected_roles)
        c_role_fn = len(expected_roles - detected_roles)
        
        role_tp += c_role_tp
        role_fp += c_role_fp
        role_fn += c_role_fn

        if detected_roles == expected_roles:
            role_correct_contracts += 1

        # 2. Function Evaluation (evaluated on public/external AA functions)
        detected_funcs = set([f.name for f in facts.functions if f.is_external_or_public])
        expected_funcs = set(spec.get("expected_functions", []))

        c_func_tp = len(detected_funcs & expected_funcs)
        c_func_fp = len(detected_funcs - expected_funcs)
        c_func_fn = len(expected_funcs - detected_funcs)

        func_tp += c_func_tp
        func_fp += c_func_fp
        func_fn += c_func_fn

        # 3. State Tag Evaluation
        detected_tags = {sv.name: sv.role_tag for sv in facts.state_variables if sv.role_tag}
        expected_tags = spec.get("expected_state_tags", {})

        c_tag_tp = 0
        c_tag_fp = 0
        c_tag_fn = 0

        for var, exp_tag in expected_tags.items():
            if var in detected_tags and detected_tags[var] == exp_tag:
                c_tag_tp += 1
            else:
                c_tag_fn += 1

        for var, det_tag in detected_tags.items():
            if var not in expected_tags or expected_tags[var] != det_tag:
                c_tag_fp += 1

        tag_tp += c_tag_tp
        tag_fp += c_tag_fp
        tag_fn += c_tag_fn

        # 4. Dataflow Read Evaluation (Crucial for SessionAccount & CouponPaymaster bug detection)
        expected_df_reads = spec.get("expected_dataflow_reads", {})
        c_df_tp = 0
        c_df_fp = 0
        c_df_fn = 0

        df_summary = {}
        for func_name, exp_reads in expected_df_reads.items():
            df_obj = next((df for df in facts.data_flows if df.function_name == func_name), None)
            det_reads = set(df_obj.state_vars_read) if df_obj else set()
            exp_reads_set = set(exp_reads)

            tp = len(det_reads & exp_reads_set)
            fp = len(det_reads - exp_reads_set)
            fn = len(exp_reads_set - det_reads)

            c_df_tp += tp
            c_df_fp += fp
            c_df_fn += fn

            df_summary[func_name] = {
                "detected": list(det_reads),
                "expected": list(exp_reads_set),
                "correct": list(det_reads & exp_reads_set)
            }

        df_tp += c_df_tp
        df_fp += c_df_fp
        df_fn += c_df_fn

        f_prec = c_func_tp / (c_func_tp + c_func_fp) if (c_func_tp + c_func_fp) > 0 else 1.0
        f_rec = c_func_tp / (c_func_tp + c_func_fn) if (c_func_tp + c_func_fn) > 0 else 1.0
        t_prec = c_tag_tp / (c_tag_tp + c_tag_fp) if (c_tag_tp + c_tag_fp) > 0 else 1.0
        t_rec = c_tag_tp / (c_tag_tp + c_tag_fn) if (c_tag_tp + c_tag_fn) > 0 else 1.0
        d_prec = c_df_tp / (c_df_tp + c_df_fp) if (c_df_tp + c_df_fp) > 0 else 1.0
        d_rec = c_df_tp / (c_df_tp + c_df_fn) if (c_df_tp + c_df_fn) > 0 else 1.0

        # Strict PASS requires clearing both precision and recall floors
        is_pass = (
            detected_roles == expected_roles
            and f_prec >= 0.50
            and f_rec >= 0.80
            and d_prec >= 0.80
            and d_rec >= 0.80
        )

        contract_results.append({
            "file_name": file_name,
            "roles_match": detected_roles == expected_roles,
            "detected_roles": list(detected_roles),
            "expected_roles": list(expected_roles),
            "func_precision": f_prec,
            "func_recall": f_rec,
            "tag_precision": t_prec,
            "tag_recall": t_rec,
            "df_precision": d_prec,
            "df_recall": d_rec,
            "is_pass": is_pass,
            "dataflow_reads": df_summary
        })

    # Summary Metrics
    role_acc = role_correct_contracts / total_contracts if total_contracts > 0 else 0.0
    role_prec = role_tp / (role_tp + role_fp) if (role_tp + role_fp) > 0 else 1.0
    role_rec = role_tp / (role_tp + role_fn) if (role_tp + role_fn) > 0 else 1.0

    func_prec = func_tp / (func_tp + func_fp) if (func_tp + func_fp) > 0 else 1.0
    func_rec = func_tp / (func_tp + func_fn) if (func_tp + func_fn) > 0 else 1.0

    tag_prec = tag_tp / (tag_tp + tag_fp) if (tag_tp + tag_fp) > 0 else 1.0
    tag_rec = tag_tp / (tag_tp + tag_fn) if (tag_tp + tag_fn) > 0 else 1.0

    df_prec = df_tp / (df_tp + df_fp) if (df_tp + df_fp) > 0 else 1.0
    df_rec = df_tp / (df_tp + df_fn) if (df_tp + df_fn) > 0 else 1.0

    summary = {
        "total_contracts": total_contracts,
        "role_accuracy": role_acc,
        "role_precision": role_prec,
        "role_recall": role_rec,
        "function_precision": func_prec,
        "function_recall": func_rec,
        "tag_precision": tag_prec,
        "tag_recall": tag_rec,
        "dataflow_read_precision": df_prec,
        "dataflow_read_recall": df_rec,
    }

    # Generate Markdown Table Report
    md_lines = [
        "# SpecGuard-AA Stage 1 Fact Extraction Evaluation Results",
        "",
        "## Summary Metrics",
        "",
        "| Metric Class | Score | Notes / Target Floor |",
        "| --- | --- | --- |",
        f"| **Role Identification Accuracy** | **{role_acc * 100:.1f}%** ({role_correct_contracts}/{total_contracts}) | Target Floor >= 85.0% |",
        f"| **Function Detection Precision** | {func_prec * 100:.1f}% | Evaluated on public/external interface functions |",
        f"| **Function Detection Recall** | {func_rec * 100:.1f}% | Target function coverage |",
        f"| **State Tag Precision** | {tag_prec * 100:.1f}% | Role tagging heuristic precision |",
        f"| **State Tag Recall** | {tag_rec * 100:.1f}% | Role tagging coverage |",
        f"| **DATAFLOW READ PRECISION (PROMINENT)** | **{df_prec * 100:.1f}%** | State vars read during validation (constants filtered) |",
        f"| **DATAFLOW READ RECALL (PROMINENT)** | **{df_rec * 100:.1f}%** | Underlies SessionAccount & CouponPaymaster bug detection |",
        "",
        "---",
        "",
        "## Contract-by-Contract Breakdown",
        "",
        "| Contract | Roles (Det / Exp) | Func Prec/Rec | Tag Prec/Rec | **Dataflow Read Prec/Rec** | Status |",
        "| --- | --- | --- | --- | --- | --- |"
    ]

    for cr in contract_results:
        status_icon = "PASS" if cr["is_pass"] else "LIMITATION"
        md_lines.append(
            f"| `{cr['file_name']}` | `{','.join(cr['detected_roles'])}` / `{','.join(cr['expected_roles'])}` | "
            f"{cr['func_precision']*100:.0f}% / {cr['func_recall']*100:.0f}% | "
            f"{cr['tag_precision']*100:.0f}% / {cr['tag_recall']*100:.0f}% | "
            f"**{cr['df_precision']*100:.0f}% / {cr['df_recall']*100:.0f}%** | `{status_icon}` |"
        )

    md_report = "\n".join(md_lines)
    
    report_file = os.path.join(benchmark_dir, "EVAL_RESULTS.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(md_report)

    return {
        "summary": summary,
        "contract_results": contract_results,
        "markdown_report": md_report
    }


if __name__ == "__main__":
    res = evaluate_benchmark()
    print(res["markdown_report"])
    print("\n[+] Evaluation report generated at benchmark/stage1_fact_extraction/EVAL_RESULTS.md")
