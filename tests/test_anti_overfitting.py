# SPDX-License-Identifier: MIT
"""
Anti-Overfitting Verification Suite for SpecGuard-AA (Item 1).
Tests pipeline generalization against two unseen contracts:
1. SimpleOwnerAccount.sol (Clean owner-only smart account)
2. ExpirySessionAccount.sol (Session key account with missing expiration check)
"""

import os
import pytest
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder
from specguard.models import PropertyType, Role


SIMPLE_OWNER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SimpleOwnerAccount.sol"
)
EXPIRY_SESSION_PATH = os.path.join(
    "contracts", "src", "worked_examples", "ExpirySessionAccount.sol"
)


def test_anti_overfitting_clean_contract():
    """
    Contract (a): Clean owner-only account with validateUserOp, no session keys.
    Verification: Stays quiet - no false session-key or paymaster property is bound.
    """
    facts = extract_facts(SIMPLE_OWNER_PATH)

    assert facts.contract_name == "SimpleOwnerAccount"
    assert Role.ACCOUNT in facts.roles
    assert facts.get_state_var("sessionKey") is None
    assert facts.get_state_var("allowedTarget") is None

    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    kept_props = []

    for p in raw_props:
        res = binder.process(p, facts, evidence)
        if res:
            kept_props.append(res[0])

    # Confirm NO session key or paymaster properties survive binding
    session_props = [p for p in kept_props if p.template_type == PropertyType.SESSION]
    paymaster_props = [p for p in kept_props if p.template_type == PropertyType.PAYMASTER]

    assert len(session_props) == 0, "Clean contract must NOT bind any session key property"
    assert len(paymaster_props) == 0, "Clean contract must NOT bind any paymaster property"


def test_anti_overfitting_different_bug_shape():
    """
    Contract (b): Session key account where target check is present, but expiry check is missing.
    Verification: Finds a DIFFERENT property (Expiration policy failure) than SessionAccount.sol.
    """
    facts = extract_facts(EXPIRY_SESSION_PATH)

    assert facts.contract_name == "ExpirySessionAccount"
    assert Role.ACCOUNT in facts.roles
    assert facts.get_state_var("sessionExpiry") is not None

    # Check data flow: allowedTarget IS read in validateUserOp, but sessionExpiry is NOT
    val_df = next(df for df in facts.data_flows if df.function_name == "validateUserOp")
    assert "allowedTarget" in val_df.state_vars_read, "Target check exists in validateUserOp"
    assert "sessionExpiry" not in val_df.state_vars_read, "Expiration check is missing in validateUserOp"

    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    kept_props = []

    for p in raw_props:
        res = binder.process(p, facts, evidence)
        if res:
            kept_props.append(res[0])

    # Confirm that it finds an EXPIRY property (different bug shape than SessionAccount target bypass)
    expiry_prop = next(
        (p for p in kept_props if p.template_type == PropertyType.SESSION and "notExpired" in p.required_condition),
        None
    )
    assert expiry_prop is not None, (
        "Must discover and bind the missing session key expiration property for ExpirySessionAccount"
    )
    assert expiry_prop.bindings.custom_bindings.get("expiry_mapping") == "sessionExpiry"
