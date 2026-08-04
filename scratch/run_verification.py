# SPDX-License-Identifier: MIT
import os
import json
import shutil
from dotenv import load_dotenv

from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder

load_dotenv()

# Clear cache to guarantee live calls
shutil.rmtree('.cache/llm_synthesis', ignore_errors=True)

corpus = load_corpus("corpus")
retriever = HybridRetriever(corpus)
synthesizer = PropertySynthesizer(live=True)
binder = NormalizerAndBinder()

target_files = [
    ("SessionAccount.sol", "contracts/src/worked_examples/SessionAccount.sol"),
    ("ExpirySessionAccount.sol", "contracts/src/worked_examples/ExpirySessionAccount.sol"),
    ("CouponPaymaster.sol", "contracts/src/worked_examples/CouponPaymaster.sol"),
]

results = {}

for label, file_path in target_files:
    facts = extract_facts(file_path)
    queries = build_queries(facts)
    evidence = retriever.retrieve_all_for_contract(queries, facts)
    
    prompt = synthesizer.get_llm_prompt(facts, evidence)
    raw_props = synthesizer.synthesize(facts, evidence, force_live=True)
    
    bound_props = []
    for p in raw_props:
        res = binder.process(p, facts, evidence)
        if res:
            bound_props.append(res)
            
    # Find property with raw SDK envelope
    raw_sdk_envelope = None
    for p in raw_props:
        if p.raw_prompt_response and ("chatcmpl" in p.raw_prompt_response or "id" in p.raw_prompt_response):
            raw_sdk_envelope = p.raw_prompt_response
            break
    if not raw_sdk_envelope and raw_props:
        raw_sdk_envelope = raw_props[0].raw_prompt_response

    results[label] = {
        "prompt": prompt,
        "raw_sdk_envelope": raw_sdk_envelope,
        "raw_props": [p.model_dump() for p in raw_props],
        "bound_props": [
            {
                "property": pair[0].model_dump(),
                "binding": pair[1].model_dump(),
            }
            for pair in bound_props
        ]
    }

with open("scratch/live_verification_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("[+] Live verification completed successfully! Results written to scratch/live_verification_results.json")
