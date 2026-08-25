# SPDX-License-Identifier: MIT
"""
Halmos Symbolic Validation Backend Tests (Paper Section 3.4 & 5.2).
Validates symbolic harness generation where signatures are kept concrete
while policy parameters (target, timestamp, coupon) are evaluated symbolically.

Test expectations:
  positive fixture (SessionAccount)   — Halmos finds [FAIL] counterexample → Witness returned.
  negative fixture (SimpleOwnerAccount) — Halmos proves all checks pass  → None (⊥) returned.
"""

import os
import json
import shutil
import subprocess
import pytest

from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder
from specguard.backends.halmos_symbolic import HalmosSymbolicBackend
from specguard.models import PropertyType, Role, Property, PropertyBinding

SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
SIMPLE_OWNER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SimpleOwnerAccount.sol"
)


def has_halmos() -> bool:
    """
    Detect Halmos executable: checks native PATH first, then the explicit
    WSL2 path ~/.local/bin/halmos (which is NOT on $PATH by default in most
    WSL2 distributions but is where `pip install halmos` places the binary).
    """
    if shutil.which("halmos"):
        return True
    # Probe the explicit WSL2 installation path.
    for probe_cmd in (
        ["wsl", "~/.local/bin/halmos", "--version"],
        ["wsl", "bash", "-lc", "halmos --version"],
    ):
        try:
            res = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0 and "halmos" in (res.stdout + res.stderr).lower():
                return True
        except Exception:
            continue
    return False


HALMOS_AVAILABLE = has_halmos()

# ---------------------------------------------------------------------------
# Positive fixture — SessionAccount (policy violation expected)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not HALMOS_AVAILABLE,
    reason=(
        "Halmos SMT solver not reachable. "
        "Install via: wsl pip install halmos  "
        "Confirmed path: ~/.local/bin/halmos in WSL2 Linux env."
    ),
)
def test_halmos_backend_positive_fixture():
    """
    Positive Fixture: SessionAccount session-target policy bypass.

    The harness sets unauthorizedTarget as a symbolic SMT free variable while
    keeping the ECDSA signature concrete (vm.mockCall recovers sessionKey).
    Halmos should find a counterexample where validateUserOp returns 0
    (success) for an unauthorizedTarget, producing a Witness.
    """
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence, mode="full_specguard")

    binder = NormalizerAndBinder()
    bound_results = [
        res
        for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res is not None
    ]

    session_pair = next(
        (res for res in bound_results if res[0].template_type == PropertyType.SESSION),
        None,
    )

    # If synthesizer didn't produce a SESSION property (e.g. cache miss), build one directly.
    if session_pair is None:
        session_prop = Property(
            property_id="PROP_SESSION_KEY_VALIDATION",
            target_role=Role.ACCOUNT,
            template_type=PropertyType.SESSION,
            precondition="signedBySessionKey(op, sessionKey)",
            required_condition="target(op) == allowedTarget[K]",
            description="Session key target policy: signed op must target allowedTarget",
        )
        binding = PropertyBinding(
            property_id="PROP_SESSION_KEY_VALIDATION",
            target_policy_mapping=json.dumps({"allowedTarget": "allowedTarget"}),
            is_bound=True,
        )
    else:
        session_prop, binding = session_pair

    halmos_backend = HalmosSymbolicBackend()
    witness = halmos_backend.validate(session_prop, binding, facts)

    assert witness is not None, (
        "Positive fixture FAILED: Halmos symbolic backend must find a counterexample "
        "(policy bypass) for SessionAccount's target policy invariant."
    )
    assert witness.backend == "HalmosSymbolic"
    assert witness.is_valid is True
    assert len(witness.trace_events) > 0, "Witness must include at least one [FAIL] trace line."
    print(f"\n[PASS] Halmos counterexample found: {witness.trace_events}")


# ---------------------------------------------------------------------------
# Negative fixture — SimpleOwnerAccount (no violation expected)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not HALMOS_AVAILABLE,
    reason=(
        "Halmos SMT solver not reachable. "
        "Install via: wsl pip install halmos  "
        "Confirmed path: ~/.local/bin/halmos in WSL2 Linux env."
    ),
)
def test_halmos_backend_negative_fixture():
    """
    Negative Fixture: SimpleOwnerAccount owner-auth property.

    All symbolic attacker addresses are rejected by the clean owner check —
    Halmos should prove the invariant holds for all inputs and return ⊥ (None).
    """
    facts = extract_facts(SIMPLE_OWNER_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    retriever = HybridRetriever(corpus)
    evidence = retriever.retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer()
    raw_props = synthesizer.synthesize(facts, evidence, mode="full_specguard")

    binder = NormalizerAndBinder()
    bound_results = [
        res
        for res in (binder.process(p, facts, evidence) for p in raw_props)
        if res is not None
    ]

    auth_pair = next(
        (res for res in bound_results if res[0].template_type == PropertyType.AUTH),
        None,
    )

    if auth_pair is None:
        auth_prop = Property(
            property_id="PROP_OWNER_AUTH_HALMOS",
            target_role=Role.ACCOUNT,
            template_type=PropertyType.AUTH,
            precondition="signedByOwner(op, owner)",
            required_condition="validSignature(op, owner)",
            description="Owner auth: only owner-signed ops may succeed",
        )
        binding = PropertyBinding(
            property_id="PROP_OWNER_AUTH_HALMOS",
            target_policy_mapping=json.dumps({"owner": "owner"}),
            is_bound=True,
        )
    else:
        auth_prop, binding = auth_pair

    halmos_backend = HalmosSymbolicBackend()
    witness = halmos_backend.validate(auth_prop, binding, facts)

    assert witness is None, (
        "Negative fixture FAILED: Clean SimpleOwnerAccount must return _|_ (None) - "
        "Halmos proved all symbolic check_ functions pass without counterexample."
    )
    print("\n[PASS] Halmos returned _|_ (None) - no unauthorized bypass found for SimpleOwnerAccount.")
