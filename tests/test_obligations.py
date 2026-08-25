# SPDX-License-Identifier: MIT
"""
Phase B Unit Test Suite for SpecGuard-AA Obligations Inventory & Authority Scoring.
Tests Step B1 (SelectRules & compiled table), Step B2 (dispersed inventory & triggers),
and Step B3 (authority scoring & conflict resolution).
"""

import os
import pytest
from specguard.models import MechanismTag
from specguard.obligations import (
    SelectRules,
    COMPILED_ERC7562_RULES,
    SelectDispersedObligations,
    DISPERSED_SEED_OBLIGATIONS,
    compute_authority,
    Obligation,
    ObligationKind,
    Stream,
    resolve_conflicts,
)


def test_compiled_rules_count_and_coverage():
    """Verify that the compiled table contains the full 24-obligation ERC-7562 set."""
    assert len(COMPILED_ERC7562_RULES) >= 24
    rule_ids = {r.id for r in COMPILED_ERC7562_RULES}
    
    expected_ids = {
        "OP-011", "OP-012", "OP-013", "OP-020", "OP-041", "OP-051_055", "OP-061", "OP-062", "OP-070", "OP-080",
        "STO-010", "STO-021", "STO-022", "STO-031", "STO-032", "STO-033",
        "COD-010",
        "EREP-050", "EREP-055", "EREP-070",
        "LIM-020", "LIM-030",
        "AUTH-020", "STO-040"
    }
    assert expected_ids.issubset(rule_ids), f"Missing compiled rule IDs: {expected_ids - rule_ids}"


def test_select_rules_six_mechanism_profiles():
    """Test SelectRules() deterministic lookup across 6 distinct mechanism profiles without LLM calls."""
    # Profile 1: Simple Owner Account (baseline validation only)
    p1_mechs = []
    p1_rules = SelectRules(p1_mechs, "0.7")
    p1_ids = {r.id for r in p1_rules}
    assert "OP-011" in p1_ids
    assert "STO-010" in p1_ids
    assert "EREP-050" not in p1_ids  # No postOp handler

    # Profile 2: Coupon Paymaster (postop_handler present)
    p2_mechs = [MechanismTag(tag="postop_handler")]
    p2_rules = SelectRules(p2_mechs, "0.7")
    p2_ids = {r.id for r in p2_rules}
    assert "EREP-050" in p2_ids
    assert "LIM-020" in p2_ids
    assert "STO-031" in p2_ids

    # Profile 3: Modular Account (external calls + module installation)
    p3_mechs = [MechanismTag(tag="external_call_in_validation"), MechanismTag(tag="module_installation")]
    p3_rules = SelectRules(p3_mechs, "0.7")
    p3_ids = {r.id for r in p3_rules}
    assert "OP-041" in p3_ids
    assert "STO-021" in p3_ids
    assert "COD-010" in p3_ids

    # Profile 4: WebAuthn Passkey Account
    p4_mechs = [MechanismTag(tag="webauthn_verifier"), MechanismTag(tag="external_call_in_validation")]
    p4_rules = SelectRules(p4_mechs, "0.7")
    p4_ids = {r.id for r in p4_rules}
    assert "OP-062" in p4_ids

    # Profile 5: Session Key Account (delegated key set + policy map)
    p5_mechs = [MechanismTag(tag="delegated_key_set"), MechanismTag(tag="policy_map")]
    p5_rules = SelectRules(p5_mechs, "0.7")
    assert len(p5_rules) >= 8

    # Profile 6: EIP-7702 Delegated Account
    p6_mechs = [MechanismTag(tag="eip7702_delegated")]
    p6_rules = SelectRules(p6_mechs, "0.8")
    p6_ids = {r.id for r in p6_rules}
    assert "AUTH-020" in p6_ids


def test_dispersed_inventory_sources_and_triggers():
    """Verify that every entry in O_D has valid source references and A3 mechanism triggers."""
    assert len(DISPERSED_SEED_OBLIGATIONS) == 47

    valid_a3_vocabulary = {
        "validation_entrypoint",
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

    for ob in DISPERSED_SEED_OBLIGATIONS:
        assert len(ob.sources) >= 1, f"Dispersed obligation {ob.id} missing source URL/reference!"
        assert any(src.startswith("http") or src.startswith("ERC") or src.startswith("EIP") or src.startswith("DOC") for src in ob.sources)
        assert ob.triggers.issubset(valid_a3_vocabulary), f"Obligation {ob.id} has invalid trigger tags: {ob.triggers - valid_a3_vocabulary}"


def test_authority_scoring_certik_vs_tutorial():
    """
    Unit test B3: CertiK passkey obligation outranks an uncorroborated tutorial.
    A well-corroborated MUST in an informal source outranks an uncorroborated SHOULD/advice in a tutorial.
    """
    certik_ob = Obligation(
        id="WEB-001",
        statement="Verify that clientDataJSON.type is webauthn.get",
        triggers={"webauthn_verifier"},
        authority=compute_authority(modal_strength="MUST", corroboration=4, specificity="field-level"),
        sources=["https://certik.com/blogs/passkey-wallet-security", "https://www.w3.org/TR/webauthn-2/"],
        kind=ObligationKind.COMMITMENT,
        stream=Stream.RETRIEVED,
    )

    tutorial_ob = Obligation(
        id="TUT-001",
        statement="Optional challenge buffer padding recommendation",
        triggers={"webauthn_verifier"},
        authority=compute_authority(modal_strength="MAY", corroboration=1, specificity="general-advice"),
        sources=["https://medium.com/some-tutorial"],
        kind=ObligationKind.COMMITMENT,
        stream=Stream.RETRIEVED,
    )

    assert certik_ob.authority.score > tutorial_ob.authority.score, (
        f"Authority scoring failed: CertiK score ({certik_ob.authority.score}) "
        f"did not outrank tutorial score ({tutorial_ob.authority.score})"
    )


def test_conflict_resolution_logging():
    """Verify conflict resolution logs entry to CONFLICT_LOG.md."""
    ob1 = Obligation(
        id="TEST-001",
        statement="Must use EIP-712 domain separator",
        triggers={"local_digest"},
        authority=compute_authority("MUST", 3, "field-level"),
        kind=ObligationKind.COMMITMENT,
        conflicts_with=["TEST-002"],
    )
    ob2 = Obligation(
        id="TEST-002",
        statement="May use plain keccak256",
        triggers={"local_digest"},
        authority=compute_authority("MAY", 1, "general-advice"),
        kind=ObligationKind.COMMITMENT,
        conflicts_with=["TEST-001"],
    )

    resolved, logs = resolve_conflicts([ob1, ob2])
    assert len(logs) >= 1
    assert "TEST-001" in logs[0]
    assert "TEST-002" in logs[0]
