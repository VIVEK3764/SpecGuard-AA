# SPDX-License-Identifier: MIT
"""
SpecGuard-AA Command Line Interface.
Step 1: Extract contract facts E(c).
Step 2: Hybrid Retrieval of relevant protocol requirement chunks D from corpus.
Step 3: Template-first property synthesis P_raw (supports --live LLM API synthesis).
Step 4: Normalization, Type-checking, and Symbol Binding.
"""

import sys
import json
import argparse
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder


def main():
    parser = argparse.ArgumentParser(
        description="SpecGuard-AA: Retrieval-Augmented Specification Mining for Account Abstraction"
    )
    parser.add_argument(
        "solidity_file",
        help="Path to target Solidity contract file",
    )
    parser.add_argument(
        "--contract",
        dest="contract_name",
        help="Specific contract name to analyze (optional)",
        default=None,
    )
    parser.add_argument(
        "--retrieve",
        action="store_true",
        help="Perform requirement retrieval from corpus using E(c)",
    )
    parser.add_argument(
        "--synthesize",
        action="store_true",
        help="Synthesize and bind candidate properties from E(c) and retrieved context",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform live LLM API call for property synthesis using .env credentials",
    )
    parser.add_argument(
        "--corpus-dir",
        default="corpus",
        help="Directory containing corpus JSON files",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output_file",
        help="Path to save output JSON",
        default=None,
    )

    args = parser.parse_args()

    try:
        # Step 1: Extract Facts E(c)
        facts = extract_facts(args.solidity_file, target_contract_name=args.contract_name)
        result_dict = facts.model_dump()

        # Step 2: Hybrid Retrieval
        corpus = load_corpus(args.corpus_dir)
        queries = build_queries(facts)
        retriever = HybridRetriever(corpus)
        retrieved_chunks = retriever.retrieve_all_for_contract(queries, facts)

        if args.retrieve or args.synthesize:
            result_dict["retrieval_queries"] = [q.model_dump() for q in queries]
            result_dict["retrieved_evidence"] = [c.model_dump() for c in retrieved_chunks]

        # Step 3 & 4: Synthesis & Binding
        if args.synthesize:
            synthesizer = PropertySynthesizer(live=args.live)
            raw_props = synthesizer.synthesize(facts, retrieved_chunks, force_live=args.live)

            binder = NormalizerAndBinder()
            normalized_and_bound = []

            for p in raw_props:
                res = binder.process(p, facts, retrieved_chunks)
                if res:
                    norm_prop, binding = res
                    prop_data = norm_prop.model_dump()
                    prop_data["binding"] = binding.model_dump()
                    normalized_and_bound.append(prop_data)

            result_dict["synthesized_properties"] = [p.model_dump() for p in raw_props]
            result_dict["normalized_and_bound_properties"] = normalized_and_bound

        json_output = json.dumps(result_dict, indent=2)

        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] Saved analysis output to {args.output_file}")
        else:
            print(json_output)

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
