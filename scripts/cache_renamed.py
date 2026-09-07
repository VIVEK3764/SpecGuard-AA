import os
import sys
import glob
import json
from specguard.extractor import extract_facts
from specguard.synthesis.synthesizer import PropertySynthesizer, CACHE_DIR
from tests.test_rename_invariance import _create_renamed_contract

contracts = [
    ("benchmark/stage1_fact_extraction/contracts/SessionAccount.sol", "SES-001"),
    ("benchmark/stage1_fact_extraction/contracts/CouponPaymaster.sol", "PAY-004"),
    ("benchmark/stage1_fact_extraction/contracts/ExpirySessionAccount.sol", "SES-004"),
    ("benchmark/stage1_fact_extraction/contracts/SimpleOwnerAccount.sol", "SIG-001"),
]

synthesizer = PropertySynthesizer()
scratch_dir = os.path.abspath("scratch/renamed_contracts")

def save_cache(facts, evidence_chunks, obligation_id, mode, properties):
    cache_key = synthesizer._get_cache_key(facts, evidence_chunks, obligation_id, mode)
    cache_path = os.path.join(CACHE_DIR, f"{cache_key}.json")
    payload = {"properties": [p.model_dump() for p in properties]}
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"Cached {len(properties)} for {facts.contract_name} ({obligation_id}) -> {cache_key}.json")

for sol_path, obl_id in contracts:
    orig_facts = extract_facts(sol_path)
    orig_props = synthesizer.synthesize(orig_facts, [], obligation_id=obl_id, mode="full_specguard")
    
    renamed_path, renamed_name = _create_renamed_contract(sol_path, scratch_dir)
    renamed_facts = extract_facts(renamed_path, target_contract_name=renamed_name)
    save_cache(renamed_facts, [], obl_id, "full_specguard", orig_props)
    save_cache(renamed_facts, [], "OBL-AA-001", "full_specguard", orig_props)

print("Renamed cache saved.")
