# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA Phase-Guided Retrieval Filtering (Paper Section 4.1).
Proves that phase metadata filtering (deployment vs validation vs postOp)
selectively filters retrieved evidence chunks.
"""

import os
import pytest
from specguard.models import ContractFacts, Role, AAFact
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import RetrievalQuery
from specguard.retrieval.retriever import HybridRetriever


def test_phase_filtering_deployment_vs_validation():
    corpus = load_corpus("corpus")
    retriever = HybridRetriever(corpus)

    # 1. Deployment-Phase Query (Factory account creation)
    deploy_query = RetrievalQuery(
        query_text="account factory deploy createAccount initialization CREATE2",
        target_role="factory",
        target_phase="deployment",
        topic="factory initialization",
    )

    factory_facts = ContractFacts(
        contract_name="SimpleAccountFactory",
        source_path="contracts/src/SimpleAccountFactory.sol",
        roles=[Role.FACTORY],
        functions=[],
        state_variables=[],
        data_flows=[],
        aa_facts=AAFact(),
    )

    deploy_results = retriever.retrieve(deploy_query, factory_facts, top_k=5)
    deploy_ids = [c.id for c in deploy_results]

    # Must contain real factory deployment spec chunk
    assert any("ERC4337-SPEC" in cid for cid in deploy_ids), "Should retrieve factory deployment requirement"

    # Must NOT contain validation-only chunks (e.g. session key or coupon requirements)
    assert not any("AUTH" in cid for cid in deploy_ids), "Validation phase chunk must be excluded by phase filter"


def test_phase_filtering_postop_vs_validation():
    corpus = load_corpus("corpus")
    retriever = HybridRetriever(corpus)

    val_query = RetrievalQuery(
        query_text="validatePaymasterUserOp sponsorship coupon signature",
        target_role="paymaster",
        target_phase="validation",
        topic="sponsorship",
    )

    paymaster_facts = ContractFacts(
        contract_name="CouponPaymaster",
        source_path="contracts/src/CouponPaymaster.sol",
        roles=[Role.PAYMASTER],
        functions=[],
        state_variables=[],
        data_flows=[],
        aa_facts=AAFact(),
    )

    val_results = retriever.retrieve(val_query, paymaster_facts, top_k=5)
    val_ids = [c.id for c in val_results]

    for cid in val_ids:
        chunk = retriever.chunk_dict[cid]
        assert chunk.matches_phase("validation"), f"Chunk {cid} must be compatible with validation phase"
