# SPDX-License-Identifier: MIT
"""
Unit and Regression Test Suite for Step C5: Per-Obligation Sentence-Level Grounding.
"""

import pytest
from specguard.models import Property, PropertyType, Role, PropertyBinding
from specguard.retrieval.corpus import CorpusChunk
from specguard.binding.grounding import SentenceLevelGroundingEngine
from specguard.binding.binder import NormalizerAndBinder


def test_grounding_rejects_unrelated_citation_auth010():
    """
    Regression Test: A session-key property citing ERC7562-AUTH-010 (EIP-7702 auth tuples)
    must be REJECTED by sentence-level grounding.
    """
    engine = SentenceLevelGroundingEngine()

    # Unrelated standard rule chunk (AUTH-010 discusses EIP-7702 authorization tuples)
    auth_010_chunk = CorpusChunk(
        id="ERC7562-AUTH-010",
        source="ERC-7562 Specification: [AUTH-010]",
        role="generic",
        phase="validation",
        topic="authorization",
        text="[AUTH-010] A transaction MUST NOT include more than one authorization tuple in the transaction authorization list.",
        authority=1.0,
    )

    prop = Property(
        property_id="PROP-SESSION-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["ERC7562-AUTH-010"],
    )

    grounded_prop, rejections = engine.validate_property_grounding(prop, [auth_010_chunk])

    assert grounded_prop is None, "Expected property citing unrelated AUTH-010 to be rejected, but it passed!"
    assert len(rejections) > 0
    assert "ERC7562-AUTH-010" in rejections[0].cited_chunk_id


def test_grounding_accepts_genuine_delegated_auth_chunk():
    """
    Regression Test: The same session-key property citing a genuine target scoping chunk
    with sentence-level normative modal co-occurrence must be ACCEPTED.
    """
    engine = SentenceLevelGroundingEngine()

    # Genuine audit recommendation chunk with sentence-level co-occurrence
    genuine_session_chunk = CorpusChunk(
        id="AUDIT-BICONOMY-001-REC",
        source="C4 Biconomy Finding: Session key scoping (Recommendation)",
        role="account",
        phase="validation",
        topic="session key",
        text="The validator must verify that the destination target contract matches the registered allowedTarget policy mapping for the session key.",
        authority=0.90,
    )

    prop = Property(
        property_id="PROP-SESSION-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["AUDIT-BICONOMY-001-REC"],
    )

    grounded_prop, rejections = engine.validate_property_grounding(prop, [genuine_session_chunk])

    assert grounded_prop is not None, "Expected property citing genuine session chunk to pass!"
    assert grounded_prop.required_condition == "target(op) == allowedTarget[K]"
    assert "AUDIT-BICONOMY-001-REC" in grounded_prop.source_chunk_ids
    assert len(rejections) == 0


def test_grounding_rejects_modal_in_different_sentence():
    """
    Test that a chunk containing a lexicon term in sentence 1 and a normative modal in sentence 2
    (not in the SAME sentence) is REJECTED.
    """
    engine = SentenceLevelGroundingEngine()

    chunk_split_sentences = CorpusChunk(
        id="SPLIT-SENTENCE-CHUNK-001",
        source="Synthetic Split Chunk",
        role="account",
        phase="validation",
        topic="session key",
        text="The contract maintains an allowedTarget mapping for each session key. Users may deploy any contract they choose.",
        authority=0.85,
    )

    prop = Property(
        property_id="PROP-SESSION-002",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["SPLIT-SENTENCE-CHUNK-001"],
    )

    grounded_prop, rejections = engine.validate_property_grounding(prop, [chunk_split_sentences])
    assert grounded_prop is None, "Expected rejection when modal is absent from the sentence containing lexicon term!"


def test_normalizer_and_binder_integration_with_grounding():
    """
    Test full NormalizerAndBinder.process() integration with sentence-level grounding.
    """
    from specguard.models import ContractFacts, StateVariableFact, FunctionFact

    binder = NormalizerAndBinder()
    genuine_chunk = CorpusChunk(
        id="AUDIT-BICONOMY-001-REC",
        source="C4 Biconomy Finding: Session key scoping",
        role="account",
        phase="validation",
        topic="session key",
        text="The validator must enforce that target is in allowedTarget whitelist.",
        authority=0.90,
    )

    facts = ContractFacts(
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
    )

    prop = Property(
        property_id="PROP-SESSION-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
        required_condition="target(op) == allowedTarget[K]",
        source_chunk_ids=["AUDIT-BICONOMY-001-REC"],
    )

    res = binder.process(prop, facts, [genuine_chunk])
    assert res is not None
    norm_p, binding = res
    assert binding.key_mapping == "sessionKey"
    assert binding.target_policy_mapping == "allowedTarget"
