# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA Property Synthesis and Normalization/Binding Engine (Steps 3 & 4).
Includes individual test cases for every property rejection path.
"""

import os
import pytest
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder
from specguard.models import PropertyType, Role, Property, PropertyBinding, StateFact, ContractFacts, AAFact


SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
COUPON_PAYMASTER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "CouponPaymaster.sol"
)


def test_synthesis_and_binding_session_account():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_properties = synthesizer.synthesize(facts, evidence)
    assert len(raw_properties) > 0

    binder = NormalizerAndBinder()
    kept_pairs = []

    for p in raw_properties:
        res = binder.process(p, facts, evidence)
        if res:
            kept_pairs.append(res)

    assert len(kept_pairs) > 0, "Should retain normalized and bound properties"

    session_prop, binding = next(
        (p, b) for p, b in kept_pairs if p.template_type == PropertyType.SESSION
    )
    assert session_prop.target_role == Role.ACCOUNT
    assert binding.validator_function == "validateUserOp"
    assert binding.key_mapping == "sessionKey"
    assert binding.target_policy_mapping == "allowedTarget"


def test_synthesis_and_binding_coupon_paymaster():
    facts = extract_facts(COUPON_PAYMASTER_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_properties = synthesizer.synthesize(facts, evidence)
    assert len(raw_properties) > 0

    binder = NormalizerAndBinder()
    kept_pairs = []

    for p in raw_properties:
        res = binder.process(p, facts, evidence)
        if res:
            kept_pairs.append(res)

    assert len(kept_pairs) > 0

    paymaster_prop, binding = next(
        (p, b) for p, b in kept_pairs if p.template_type == PropertyType.PAYMASTER
    )
    assert paymaster_prop.target_role == Role.PAYMASTER
    assert binding.validator_function == "validatePaymasterUserOp"
    assert binding.sponsor_variable == "sponsor"
    assert binding.used_coupon_mapping == "usedCoupon"


def test_rejection_unsupported_source_citation():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    binder = NormalizerAndBinder()

    hallucinated_prop = Property(
        property_id="PROP-HALLUCINATED-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["NON-EXISTENT-SOURCE-999"],
    )
    assert binder.process(hallucinated_prop, facts, corpus) is None, (
        "Must reject property with unsupported source citation"
    )


def test_rejection_unwhitelisted_property_type():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    binder = NormalizerAndBinder()

    # Create a property with an invalid / unwhitelisted template type
    invalid_type_prop = Property(
        property_id="PROP-INVALID-TYPE-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="customUnsafeCondition(op)",
        source_chunk_ids=["ERC4337-ACC-001"],
    )
    invalid_type_prop.template_type = "INVALID_UNSUPPORTED_TEMPLATE"
    assert binder.process(invalid_type_prop, facts, corpus) is None, (
        "Must reject property with unwhitelisted template type"
    )


def test_rejection_type_check_failure():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    binder = NormalizerAndBinder()

    # Attempt to apply a Paymaster property to an Account contract
    mismatched_prop = Property(
        property_id="PROP-MISMATCH-001",
        template_type=PropertyType.PAYMASTER,
        target_role=Role.PAYMASTER,
        bindings=PropertyBinding(validator_function="validatePaymasterUserOp"),
        precondition="success(validatePaymasterUserOp(op))",
        required_condition="validCoupon(op)",
        source_chunk_ids=["ERC4337-ACC-001"],
    )
    assert binder.process(mismatched_prop, facts, corpus) is None, (
        "Must reject property failing TypeCheck against contract role"
    )


def test_rejection_bind_no_candidate_match():
    # Construct contract facts without session key state variables
    account_facts = ContractFacts(
        contract_name="BasicAccount",
        source_path="contracts/src/BasicAccount.sol",
        roles=[Role.ACCOUNT],
        functions=[],
        state_variables=[],  # No session key or target state variables
        data_flows=[],
        aa_facts=AAFact(validation_functions=["validateUserOp"]),
    )
    corpus = load_corpus("corpus")
    binder = NormalizerAndBinder()

    session_prop = Property(
        property_id="PROP-SESSION-NO-VAR",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["ERC4337-ACC-002"],
    )
    assert binder.process(session_prop, account_facts, corpus) is None, (
        "Must reject property when required symbols cannot be bound"
    )


def test_rejection_bind_ambiguous_candidate_match():
    # Construct contract facts with TWO ambiguous session key mappings
    ambiguous_facts = ContractFacts(
        contract_name="AmbiguousAccount",
        source_path="contracts/src/AmbiguousAccount.sol",
        roles=[Role.ACCOUNT],
        functions=[],
        state_variables=[
            StateFact(name="sessionKey1", type_str="mapping(address => bool)", visibility="public", role_tag="session_key_map"),
            StateFact(name="sessionKey2", type_str="mapping(address => bool)", visibility="public", role_tag="session_key_map"),
        ],
        data_flows=[],
        aa_facts=AAFact(validation_functions=["validateUserOp"]),
    )
    corpus = load_corpus("corpus")
    binder = NormalizerAndBinder()

    session_prop = Property(
        property_id="PROP-SESSION-AMBIGUOUS",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["ERC4337-ACC-002"],
    )
    assert binder.process(session_prop, ambiguous_facts, corpus) is None, (
        "Must reject property when symbol binding is ambiguous"
    )
