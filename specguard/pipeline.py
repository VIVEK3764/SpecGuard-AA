# SPDX-License-Identifier: MIT
"""
SpecGuard-AA Complete End-to-End Pipeline (Paper Figure 4 Architecture).
Connects:
  1. Fact Extraction E(c) (specguard.extractor)
  2. Hybrid Retrieval C (specguard.retrieval)
  3. LLM Property Synthesis P_raw (specguard.synthesis)
  4. Normalization & Binding P_bound (specguard.binding)
  5. Backend Dispatcher & Validation (specguard.backends)
  6. CheckWitness Replay & Evidence-Backed Reporting (specguard.reporting)
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder
from specguard.backends.dispatcher import BackendDispatcher
from specguard.reporting.reporter import ReportEngine
from specguard.models import ContractFacts, Property, PropertyBinding, Witness, SecurityReport


class SpecGuardPipeline:
    """
    End-to-End SpecGuard-AA Specification Mining and Verification Pipeline.
    """

    def __init__(self, corpus_dir: str = "corpus", live_llm: bool = True):
        self.corpus_dir = corpus_dir
        self.live_llm = live_llm

        # Initialize Pipeline Components
        self.corpus = load_corpus(self.corpus_dir)
        self.retriever = HybridRetriever(self.corpus)
        self.synthesizer = PropertySynthesizer(live=self.live_llm)
        self.binder = NormalizerAndBinder()
        self.dispatcher = BackendDispatcher()
        self.reporter = ReportEngine()

    def run(self, solidity_path: str, target_contract: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute full end-to-end pipeline on a Solidity contract file.
        Returns execution transcript dictionary containing all intermediate stages and final reports.
        """
        transcript = {
            "target_file": solidity_path,
            "stage_1_facts": None,
            "stage_2_retrieved_chunks": [],
            "stage_3_synthesized_properties": [],
            "stage_4_bound_properties": [],
            "stage_5_backend_results": [],
            "stage_6_reports": [],
        }

        print(f"\n[1/6] Extracting Contract Facts E(c) for {solidity_path}...")
        facts = extract_facts(solidity_path, target_contract_name=target_contract)
        transcript["stage_1_facts"] = facts.model_dump()
        print(f"      [+] Extracted Roles: {[r.value for r in facts.roles]}")
        print(f"      [+] Functions Found: {[f.name for f in facts.functions]}")
        print(f"      [+] Validation Dataflow Reads: {[df.state_vars_read for df in facts.data_flows]}")

        print(f"\n[2/6] Executing Hybrid Retrieval C from Corpus...")
        queries = build_queries(facts)
        retrieved_chunks = self.retriever.retrieve_all_for_contract(queries, facts)
        transcript["stage_2_retrieved_chunks"] = [c.model_dump() for c in retrieved_chunks]
        print(f"      [+] Retrieved {len(retrieved_chunks)} Protocol Evidence Chunks: {[c.id for c in retrieved_chunks]}")

        print(f"\n[3/6] Synthesizing Security Properties P_raw (Live LLM API Call)...")
        raw_properties = self.synthesizer.synthesize(facts, retrieved_chunks, force_live=self.live_llm)
        transcript["stage_3_synthesized_properties"] = [p.model_dump() for p in raw_properties]
        print(f"      [+] Synthesized {len(raw_properties)} Candidate Properties:")
        for p in raw_properties:
            print(f"          - [{p.template_type.value}] {p.property_id}: {p.required_condition}")

        print(f"\n[4/4] Normalizing and Binding Properties P_bound...")
        bound_pairs = []
        for p in raw_properties:
            bound_res = self.binder.process(p, facts, retrieved_chunks)
            if bound_res:
                norm_prop, binding = bound_res
                bound_pairs.append((norm_prop, binding))
                transcript["stage_4_bound_properties"].append({
                    "property": norm_prop.model_dump(),
                    "binding": binding.model_dump()
                })
        print(f"      [+] Successfully Bound {len(bound_pairs)} / {len(raw_properties)} Properties")

        print(f"\n[5/6] Dispatching Properties to Backend Engines for Validation...")
        active_witnesses = []
        for norm_prop, binding in bound_pairs:
            target_backends = self.dispatcher.dispatch_map.get(norm_prop.template_type, [self.dispatcher.fuzz_backend])
            backend_names = [b.__class__.__name__ for b in target_backends]
            print(f"      [->] Dispatching {norm_prop.property_id} (Type: {norm_prop.template_type.value}) -> Routing to Backends: {backend_names}")
            
            witness = self.dispatcher.validate_property(norm_prop, binding, facts)
            
            if witness:
                print(f"      [!] VIOLATION FOUND! Backend '{witness.backend}' produced valid witness!")
                active_witnesses.append((norm_prop, binding, witness))
                transcript["stage_5_backend_results"].append({
                    "property_id": norm_prop.property_id,
                    "backend": witness.backend,
                    "witness": witness.model_dump()
                })
            else:
                print(f"      [+] Property Held (None returned by {backend_names})")

        print(f"\n[6/6] Replay Verification (CheckWitness) & Evidence-Backed Reporting...")
        final_reports: List[SecurityReport] = []
        for norm_prop, binding, witness in active_witnesses:
            is_valid_replay = self.reporter.check_witness(witness, facts)
            print(f"      [CheckWitness] Replaying witness for {norm_prop.property_id}... Result: {'VERIFIED' if is_valid_replay else 'REJECTED'}")
            
            if is_valid_replay:
                report = self.reporter.generate_report(norm_prop, binding, facts, witness)
                if report:
                    final_reports.append(report)
                    transcript["stage_6_reports"].append(report.model_dump())
                    print(f"      [+] SECURITY REPORT GENERATED: {report.report_id}")
                    print(f"          - Repro Script: {report.reproduction_script_path}")
                    print(f"          - Cited Chunks: {report.retrieved_sources}")

        print(f"\n=== PIPELINE COMPLETE ===")
        print(f"Target Contract: {facts.contract_name}")
        print(f"Total Synthesized Properties: {len(raw_properties)}")
        print(f"Total Validated Violations: {len(active_witnesses)}")
        print(f"Total Verified Security Reports: {len(final_reports)}\n")

        return transcript


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run full end-to-end SpecGuard-AA pipeline")
    parser.add_argument("solidity_file", help="Path to target Solidity file")
    args = parser.parse_args()

    pipeline = SpecGuardPipeline(live_llm=True)
    res = pipeline.run(args.solidity_file)
