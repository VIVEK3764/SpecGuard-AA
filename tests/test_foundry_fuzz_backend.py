# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA 5.0 (Common Backend Interface) & 5.1 (Foundry Fuzz Backend).
Validates 3 Positive Fixtures (real witnesses produced) and 1 Negative Fixture (clean contract returns ⊥).
"""

import os
import pytest
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder
from specguard.backends.dispatcher import BackendDispatcher
from specguard.models import PropertyType


SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
COUPON_PAYMASTER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "CouponPaymaster.sol"
)
EXPIRY_SESSION_PATH = os.path.join(
    "contracts", "src", "worked_examples", "ExpirySessionAccount.sol"
)
SIMPLE_OWNER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SimpleOwnerAccount.sol"
)


def test_positive_fixture_session_account():
    """Positive Fixture 1: SessionAccount.sol target policy bypass."""
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    session_prop, binding = next(
        res for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res and res[0].template_type == PropertyType.SESSION
    )

    dispatcher = BackendDispatcher()
    witness = dispatcher.validate_property(session_prop, binding, facts)

    assert witness is not None, "Foundry fuzz backend MUST produce a witness for SessionAccount target bypass"
    assert witness.backend == "FoundryFuzz"
    assert witness.is_valid is True


def test_positive_fixture_coupon_paymaster():
    """Positive Fixture 2: CouponPaymaster.sol coupon replay bypass."""
    facts = extract_facts(COUPON_PAYMASTER_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    paymaster_prop, binding = next(
        res for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res and res[0].template_type == PropertyType.PAYMASTER
    )

    dispatcher = BackendDispatcher()
    witness = dispatcher.validate_property(paymaster_prop, binding, facts)

    assert witness is not None, "Foundry fuzz backend MUST produce a witness for CouponPaymaster coupon replay"
    assert witness.backend == "FoundryFuzz"
    assert witness.is_valid is True


def test_positive_fixture_expiry_session_account():
    """Positive Fixture 3: ExpirySessionAccount.sol session expiry bypass."""
    facts = extract_facts(EXPIRY_SESSION_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    expiry_prop, binding = next(
        res for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res and res[0].template_type == PropertyType.SESSION and "notExpired" in res[0].required_condition
    )

    dispatcher = BackendDispatcher()
    witness = dispatcher.validate_property(expiry_prop, binding, facts)

    assert witness is not None, "Foundry fuzz backend MUST produce a witness for ExpirySessionAccount expiry bypass"
    assert witness.backend == "FoundryFuzz"
    assert witness.is_valid is True


def test_negative_fixture_simple_owner_account():
    """Negative Fixture 4: SimpleOwnerAccount.sol clean owner account."""
    facts = extract_facts(SIMPLE_OWNER_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence)

    binder = NormalizerAndBinder()
    nonce_prop, binding = next(
        res for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res and res[0].template_type == PropertyType.NONCE
    )

    dispatcher = BackendDispatcher()
    witness = dispatcher.validate_property(nonce_prop, binding, facts)

    assert witness is None, "Foundry fuzz backend MUST return None (⊥) for clean owner account"
