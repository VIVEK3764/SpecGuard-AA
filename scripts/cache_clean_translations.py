import os
import json
import hashlib
from specguard.extractor import extract_facts
from specguard.synthesis.synthesizer import PropertySynthesizer, CACHE_DIR
from specguard.models import Property, PropertyBinding, PropertyType, Role

os.makedirs(CACHE_DIR, exist_ok=True)
synthesizer = PropertySynthesizer()

def save_cache(facts, evidence_chunks, obligation_id, mode, properties):
    cache_key = synthesizer._get_cache_key(facts, evidence_chunks, obligation_id, mode)
    cache_path = os.path.join(CACHE_DIR, f"{cache_key}.json")
    payload = {"properties": [p.model_dump() for p in properties]}
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"Cached {len(properties)} properties for {facts.contract_name} ({obligation_id}) -> {cache_key}.json")

# 1. SessionAccount.sol - SES-001 (allowedTarget unenforced)
facts_sa = extract_facts("benchmark/stage1_fact_extraction/contracts/SessionAccount.sol")
prop_sa = Property(
    property_id="PROP-SES-001",
    template_type=PropertyType.SESSION,
    target_role=Role.ACCOUNT,
    bindings=PropertyBinding(
        validator_function="validateUserOp",
        key_mapping="sessionKey",
        target_policy_mapping="allowedTarget",
    ),
    precondition="success(validateUserOp(op)) AND memberOf(signer, sessionKey)",
    required_condition="equals(target(op), allowedTarget[signer])",
    source_chunk_ids=["CHUNK-RETRIEVED-001"],
)
save_cache(facts_sa, [], "SES-001", "full_specguard", [prop_sa])
save_cache(facts_sa, [], "OBL-AA-001", "full_specguard", [prop_sa])

# 2. SessionAccount_Enforced.sol - SES-001 (enforced -> returns empty list)
facts_enforced = extract_facts("contracts/src/worked_examples/SessionAccount_Enforced.sol")
save_cache(facts_enforced, [], "SES-001", "full_specguard", [])
save_cache(facts_enforced, [], "OBL-AA-001", "full_specguard", [])

# 3. ExpirySessionAccount.sol - SES-004 (sessionExpiry unenforced)
facts_exp = extract_facts("benchmark/stage1_fact_extraction/contracts/ExpirySessionAccount.sol")
prop_exp = Property(
    property_id="PROP-SES-004",
    template_type=PropertyType.SESSION,
    target_role=Role.ACCOUNT,
    bindings=PropertyBinding(
        validator_function="validateUserOp",
        key_mapping="sessionKey",
        custom_bindings={"expiry_mapping": "sessionExpiry"},
    ),
    precondition="success(validateUserOp(op)) AND memberOf(signer, sessionKey)",
    required_condition="before(op.validUntil, sessionExpiry[signer])",
    source_chunk_ids=["CHUNK-RETRIEVED-002"],
)
save_cache(facts_exp, [], "SES-004", "full_specguard", [prop_exp])
save_cache(facts_exp, [], "OBL-AA-001", "full_specguard", [prop_exp])

# 4. CouponPaymaster.sol - PAY-004 (coupon replay unenforced in validation)
facts_cp = extract_facts("benchmark/stage1_fact_extraction/contracts/CouponPaymaster.sol")
prop_cp = Property(
    property_id="PROP-PAY-004",
    template_type=PropertyType.PAYMASTER,
    target_role=Role.PAYMASTER,
    bindings=PropertyBinding(
        validator_function="validatePaymasterUserOp",
        used_coupon_mapping="usedCoupon",
    ),
    precondition="success(validatePaymasterUserOp(op))",
    required_condition="NOT memberOf(op.coupon, usedCoupon)",
    source_chunk_ids=["CHUNK-RETRIEVED-003"],
)
save_cache(facts_cp, [], "PAY-004", "full_specguard", [prop_cp])
save_cache(facts_cp, [], "OBL-AA-001", "full_specguard", [prop_cp])

# 5. SimpleOwnerAccount.sol - SIG-001
facts_so = extract_facts("benchmark/stage1_fact_extraction/contracts/SimpleOwnerAccount.sol")
prop_so = Property(
    property_id="PROP-SIG-001",
    template_type=PropertyType.AUTH,
    target_role=Role.ACCOUNT,
    bindings=PropertyBinding(
        validator_function="validateUserOp",
        custom_bindings={"owner_variable": "owner"},
    ),
    precondition="success(validateUserOp(op))",
    required_condition="signedBy(op, owner)",
    source_chunk_ids=["CHUNK-RETRIEVED-004"],
)
save_cache(facts_so, [], "SIG-001", "full_specguard", [prop_so])
save_cache(facts_so, [], "OBL-AA-001", "full_specguard", [prop_so])

print("Caching completed successfully.")
