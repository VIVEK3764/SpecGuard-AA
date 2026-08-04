# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA Corpus & Hybrid Retrieval Engine (Step 2).
Verifies role/phase filtering, requirement-density ranking, and targeted query retrieval.
"""

import os
import pytest
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever


SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
COUPON_PAYMASTER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "CouponPaymaster.sol"
)


def test_retrieval_session_account():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    assert len(corpus) > 0, "Corpus should contain loaded chunks"

    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)

    results = retriever.retrieve_all_for_contract(queries, facts)
    retrieved_ids = [c.id for c in results]

    # Must retrieve official ERC-7562 Auth rule & reference audit pattern
    assert any("AUTH-010" in cid for cid in retrieved_ids), (
        "Should retrieve ERC-7562 AUTH-010 rule requirement for smart account authorization"
    )
    assert any("ETH-INFINITISM" in cid for cid in retrieved_ids), (
        "Should retrieve EntryPoint reference implementation security pattern"
    )


def test_retrieval_coupon_paymaster():
    facts = extract_facts(COUPON_PAYMASTER_PATH)
    corpus = load_corpus("corpus")
    assert len(corpus) > 0

    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)

    results = retriever.retrieve_all_for_contract(queries, facts)
    retrieved_ids = [c.id for c in results]

    # Must retrieve ERC-4337 Paymaster spec section & 33Audits paymaster replay pattern
    assert any("ERC4337-SPEC" in cid for cid in retrieved_ids), (
        "Should retrieve ERC-4337 paymaster spec requirement"
    )
    assert any("33AUDITS" in cid for cid in retrieved_ids), (
        "Should retrieve 33Audits paymaster coupon replay vulnerability pattern"
    )
