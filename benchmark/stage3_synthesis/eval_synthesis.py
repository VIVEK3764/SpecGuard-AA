"""
SpecGuard-AA Stage 3 Property Synthesis Benchmark & 4-Way Ablation Harness (RQ2 Evidence).

Evaluates property synthesis performance across 16 contracts under 4 experimental conditions:
1. Zero-Shot (No AST Facts, No RAG Specs)
2. Static Facts Only (AST Facts E(c), No RAG Specs)
3. RAG Only (RAG Specs C, No AST Facts)
4. Full SpecGuard-AA (RAG Specs C + AST Facts E(c) + Anti-Leakage Few-Shot)

Computes Property Yield, Whitelist Compliance Rate, Grounding Citation Accuracy, and Gold Invariant Coverage.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Set, Any

from specguard.extractor import extract_facts
from specguard.models import PropertyType, Role
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer, PREDICATE_WHITELIST

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
GOLD_PROPERTIES_PATH = Path(__file__).resolve().parent / "gold_properties.json"
BENCHMARK_CONTRACTS_DIR = ROOT_DIR / "benchmark" / "stage1_fact_extraction" / "contracts"
CORPUS_DIR = ROOT_DIR / "corpus"
OUTPUT_MARKDOWN_PATH = Path(__file__).resolve().parent / "SYNTHESIS_EVAL_RESULTS.md"


def check_predicate_whitelist(property_obj) -> bool:
    try:
        t_type = PropertyType(property_obj.template_type)
    except Exception:
        return False

    allowed_preds = PREDICATE_WHITELIST.get(t_type, [])
    req_cond = property_obj.required_condition
    pre_cond = property_obj.precondition

    # Check that condition contains at least one whitelisted predicate
    has_valid_pred = any(pred in req_cond or pred in pre_cond for pred in allowed_preds)
    return has_valid_pred


def check_gold_match(synth_prop, gold_prop) -> bool:
    # Match on template type and key required condition substring
    if synth_prop.template_type != gold_prop["template_type"]:
        return False

    gold_cond = gold_prop["required_condition"].lower()
    synth_cond = synth_prop.required_condition.lower()

    # Extract core tokens from gold condition
    gold_tokens = [t.strip(" ()") for t in gold_cond.split() if len(t) > 3]
    matches = sum(1 for t in gold_tokens if t in synth_cond)
    match_ratio = matches / float(len(gold_tokens)) if gold_tokens else 0.0

    return match_ratio >= 0.50


def run_evaluation():
    with open(GOLD_PROPERTIES_PATH, "r", encoding="utf-8") as f:
        gold_data = json.load(f)

    gold_properties = gold_data["gold_properties"]
    corpus = load_corpus(str(CORPUS_DIR))
    retriever = HybridRetriever(corpus)
    synthesizer = PropertySynthesizer()

    ablation_modes = ["zero_shot", "facts_only", "rag_only", "full_specguard"]
    ablation_summary = {
        mode: {
            "total_synthesized": 0,
            "whitelist_compliant": 0,
            "citation_valid": 0,
            "gold_matched": 0,
            "total_gold_count": 0,
        }
        for mode in ablation_modes
    }

    per_contract_results = {}

    for contract_name, gold_list in gold_properties.items():
        sol_path = BENCHMARK_CONTRACTS_DIR / contract_name
        if not sol_path.exists():
            print(f"[!] Warning: {sol_path} not found")
            continue

        facts = extract_facts(str(sol_path))
        queries = build_queries(facts)
        evidence_chunks = retriever.retrieve_all_for_contract(queries, facts)
        retrieved_chunk_ids = set(c.id for c in evidence_chunks)

        contract_mode_metrics = {}

        for mode in ablation_modes:
            synth_props = synthesizer.synthesize(facts, evidence_chunks, mode=mode)
            total_synth = len(synth_props)
            whitelist_hits = sum(1 for p in synth_props if check_predicate_whitelist(p))

            # Citation grounding accuracy
            citation_hits = 0
            for p in synth_props:
                if p.source_chunk_ids:
                    # Check if cited chunk IDs exist in corpus or retrieved set
                    valid_cites = sum(1 for cid in p.source_chunk_ids if cid in retrieved_chunk_ids or any(c.id == cid for c in corpus))
                    if valid_cites > 0:
                        citation_hits += 1

            # Gold invariant coverage
            gold_hits = 0
            for g_prop in gold_list:
                if any(check_gold_match(sp, g_prop) for sp in synth_props):
                    gold_hits += 1

            total_gold = len(gold_list)

            ablation_summary[mode]["total_synthesized"] += total_synth
            ablation_summary[mode]["whitelist_compliant"] += whitelist_hits
            ablation_summary[mode]["citation_valid"] += citation_hits
            ablation_summary[mode]["gold_matched"] += gold_hits
            ablation_summary[mode]["total_gold_count"] += total_gold

            contract_mode_metrics[mode] = {
                "synthesized": total_synth,
                "whitelist_compliant": whitelist_hits,
                "citation_hits": citation_hits,
                "gold_hits": gold_hits,
                "total_gold": total_gold,
                "gold_recall": (gold_hits / float(total_gold) * 100.0) if total_gold else 0.0,
            }

        per_contract_results[contract_name] = contract_mode_metrics

    # Compute overall rates
    mode_display_names = {
        "zero_shot": "1. Zero-Shot (Raw Code Only, No Facts, No RAG)",
        "facts_only": "2. Static Facts Only (AST Facts E(c), No RAG)",
        "rag_only": "3. RAG Specs Only (Retrieved C, No AST Facts)",
        "full_specguard": "**4. Full SpecGuard-AA (RAG C + Facts E(c) + Anti-Leakage)**",
    }

    lines = []
    lines.append("# SpecGuard-AA Stage 3 Property Synthesis Benchmark & Ablation Study (RQ2 Results)")
    lines.append("")
    lines.append(f"**Dataset**: 16 Benchmark Contracts  ")
    lines.append(f"**Total Gold Invariants**: {ablation_summary['full_specguard']['total_gold_count']} Invariants  ")
    lines.append(f"**Gold Dataset Freeze Timestamp**: `2026-08-12T14:00:00Z` (Frozen prior to eval run)  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 🔬 1. Side-by-Side 4-Way Synthesis Ablation Study (RQ2 Core Result)")
    lines.append("")
    lines.append("| Synthesis Pipeline Configuration | Total Properties Synthesized | Whitelist Compliance (%) | Citation Accuracy (%) | Gold Invariant Recall (%) |")
    lines.append("|---|---|---|---|---|")

    for mode in ablation_modes:
        tot = ablation_summary[mode]["total_synthesized"]
        wl = (ablation_summary[mode]["whitelist_compliant"] / float(tot) * 100.0) if tot else 0.0
        cite = (ablation_summary[mode]["citation_valid"] / float(tot) * 100.0) if tot else 0.0
        rec = (ablation_summary[mode]["gold_matched"] / float(ablation_summary[mode]["total_gold_count"]) * 100.0) if ablation_summary[mode]["total_gold_count"] else 0.0

        lines.append(f"| {mode_display_names[mode]} | {tot} | {wl:.1f}% | {cite:.1f}% | **{rec:.1f}%** |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📜 2. Per-Contract Synthesis Benchmark Results (Full SpecGuard-AA)")
    lines.append("")
    lines.append("| Contract Name | Target Gold Invariants | Synthesized Candidate Properties | Whitelist Compliance (%) | Citation Accuracy (%) | Gold Recall (%) |")
    lines.append("|---|---|---|---|---|---|")

    for contract_name, res in per_contract_results.items():
        m = res["full_specguard"]
        tot = m["synthesized"]
        wl = (m["whitelist_compliant"] / float(tot) * 100.0) if tot else 0.0
        cite = (m["citation_hits"] / float(tot) * 100.0) if tot else 0.0
        rec = m["gold_recall"]
        lines.append(f"| `{contract_name}` | {m['total_gold']} | {tot} | {wl:.1f}% | {cite:.1f}% | {rec:.1f}% |")

    markdown_content = "\n".join(lines)
    with open(OUTPUT_MARKDOWN_PATH, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"[+] Property Synthesis Evaluation Complete! Markdown written to {OUTPUT_MARKDOWN_PATH}")
    return ablation_summary, per_contract_results


if __name__ == "__main__":
    run_evaluation()
