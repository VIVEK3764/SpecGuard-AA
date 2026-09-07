# SPDX-License-Identifier: MIT
"""
Phase C Unit & Verification Test Suite for SpecGuard-AA Applicability Retrieval.
Tests Step C1 (Corpus Rebuild Quality & Extended Schema) and Step C2 (Trigger Map Completeness & Leakage Defense).
"""

import os
import json
import re
import pytest
from specguard.facts.mechanisms import MechanismTag
from specguard.retrieval.corpus import load_corpus, CorpusChunk
from specguard.retrieval.trigger_map import TRIGGER_MAP, get_topics_and_probes_for_mechanisms
from specguard.retrieval.query_builder import build_queries
from specguard.models import ContractFacts, Role, StateVariableFact, FunctionFact


def test_corpus_rebuild_quality_and_schema():
    """Verify that rebuilt corpus contains >1,000 real chunks with complete metadata and no boilerplate."""
    chunks = load_corpus("corpus")
    audit_chunks = [c for c in chunks if c.id.startswith("AUDIT-")]
    
    assert len(audit_chunks) >= 1000, f"Expected >= 1000 audit chunks, got {len(audit_chunks)}"

    forbidden_boilerplate = [
        "yarn install",
        "git clone https://",
        "## Table of contents",
        "## Wardens",
        "hardhat deploy",
    ]

    for c in audit_chunks:
        assert c.source_commit != "", f"Chunk {c.id} missing git source_commit hash"
        assert 0.40 <= c.authority <= 1.0, f"Chunk {c.id} has invalid authority {c.authority}"
        assert c.kind in ["description", "recommendation", "finding", "standard"]
        assert len(c.text.strip()) >= 50, f"Chunk {c.id} text too short"

        # Boilerplate check
        for bp in forbidden_boilerplate:
            assert bp.lower() not in c.text.lower(), f"Boilerplate '{bp}' leaked into chunk {c.id}"


def test_trigger_map_completeness_a3():
    """Verify all 10 structural mechanism tags defined in Phase A3 are present in TRIGGER_MAP."""
    a3_mechanism_tags = {
        "delegated_key_set",
        "local_digest",
        "entrypoint_digest",
        "consumed_set",
        "time_bound",
        "external_call_in_validation",
        "postop_handler",
        "webauthn_verifier",
        "module_installation",
        "policy_map",
    }

    missing_tags = a3_mechanism_tags - set(TRIGGER_MAP.keys())
    assert not missing_tags, f"Missing A3 mechanisms in TRIGGER_MAP: {missing_tags}"

    for tag in a3_mechanism_tags:
        entry = TRIGGER_MAP[tag]
        assert len(entry.topics) >= 2, f"Mechanism {tag} has fewer than 2 topics"
        assert len(entry.probes) >= 2, f"Mechanism {tag} has fewer than 2 search probes"
        assert entry.date_added != "", f"Mechanism {tag} missing date_added"


def test_trigger_map_zero_leakage_and_verdicts():
    """
    Automated check: scan every topic/probe string in TRIGGER_MAP for template names
    and verdict language. Fails if any appear literally.
    """
    forbidden_template_names = [
        "AUTH", "NONCE", "SESSION", "PAYMASTER", "FACTORY", "SCOPE", "SIM"
    ]
    forbidden_verdict_words = [
        "vulnerable", "violation", "bypass", "insecure", "exploit", "bug", "attack"
    ]

    for mech, entry in TRIGGER_MAP.items():
        all_strings = entry.topics + entry.probes
        for s in all_strings:
            s_tokens = re.findall(r"\b\w+\b", s.upper())
            for tmpl in forbidden_template_names:
                assert tmpl not in s_tokens, (
                    f"LEAKAGE DETECTED in mechanism '{mech}': template name '{tmpl}' found in '{s}'"
                )

            s_lower = s.lower()
            for verdict in forbidden_verdict_words:
                assert verdict not in s_lower, (
                    f"VERDICT LANGUAGE DETECTED in mechanism '{mech}': verdict word '{verdict}' found in '{s}'"
                )


def test_query_builder_rename_invariance():
    """Verify that query generation produces identical queries regardless of state variable names."""
    # Base facts with standard naming
    facts_orig = ContractFacts(
        contract_name="SessionAccount",
        source_path="contracts/src/worked_examples/SessionAccount.sol",
        roles=[Role.ACCOUNT],
        state_variables=[
            StateVariableFact(name="sessionKey", type_str="mapping(address => address)", visibility="public", role_tag="session_key_map"),
            StateVariableFact(name="allowedTarget", type_str="mapping(address => address)", visibility="public", role_tag="allowed_target_map"),
        ],
        functions=[
            FunctionFact(name="validateUserOp", visibility="external", is_view=False, is_pure=False, state_variables_read=["sessionKey"]),
        ],
        mechanism_tags=[MechanismTag(tag="delegated_key_set"), MechanismTag(tag="policy_map")],
    )

    # Renamed facts with obfuscated/anonymized variable names
    facts_renamed = ContractFacts(
        contract_name="C_0",
        source_path="contracts/src/worked_examples/C_0.sol",
        roles=[Role.ACCOUNT],
        state_variables=[
            StateVariableFact(name="sv_0", type_str="mapping(address => address)", visibility="public", role_tag="session_key_map"),
            StateVariableFact(name="sv_1", type_str="mapping(address => address)", visibility="public", role_tag="allowed_target_map"),
        ],
        functions=[
            FunctionFact(name="validateUserOp", visibility="external", is_view=False, is_pure=False, state_variables_read=["sv_0"]),
        ],
        mechanism_tags=[MechanismTag(tag="delegated_key_set"), MechanismTag(tag="policy_map")],
    )

    queries_orig = build_queries(facts_orig)
    queries_renamed = build_queries(facts_renamed)

    query_texts_orig = [q.query_text for q in queries_orig]
    query_texts_renamed = [q.query_text for q in queries_renamed]

    # Must produce identical queries
    assert query_texts_orig == query_texts_renamed, (
        f"Query generation is NOT rename-invariant!\nOrig: {query_texts_orig}\nRenamed: {query_texts_renamed}"
    )
    
    # Must NOT contain original variable names
    for q in query_texts_orig:
        assert "allowedTarget" not in q, f"Leaked variable name allowedTarget in query: {q}"
        assert "sessionKey" not in q, f"Leaked variable name sessionKey in query: {q}"
