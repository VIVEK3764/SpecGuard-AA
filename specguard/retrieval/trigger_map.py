# SPDX-License-Identifier: MIT
"""
Mechanism-to-Topic Trigger Map for SpecGuard-AA Applicability Retrieval (Step C2).
Pure structural bridge from mechanism tags to normative search topics and probes.
Guaranteed to contain zero property-type names (AUTH, NONCE, SESSION, PAYMASTER, FACTORY, SCOPE, SIM)
and zero verdict language (vulnerable, violation, bypass, insecure, exploit, bug, attack).
"""

from typing import Dict, List, Set, Tuple
from pydantic import BaseModel, Field


class TriggerEntry(BaseModel):
    mechanism: str
    topics: List[str]
    probes: List[str]
    date_added: str = "2026-09-01"


TRIGGER_MAP: Dict[str, TriggerEntry] = {
    # 1. delegated_key_set
    "delegated_key_set": TriggerEntry(
        mechanism="delegated_key_set",
        topics=["target boundary restriction", "expiry", "revocation", "selector limit"],
        probes=[
            "delegated signer target contract restriction check",
            "delegated signer function selector restriction enforcement",
            "delegated key expiration timestamp validity window",
            "delegated key immediate revocation state invalidation",
            "delegated key unauthorized administrative action restriction",
        ],
        date_added="2026-09-01",
    ),

    # 2. local_digest
    "local_digest": TriggerEntry(
        mechanism="local_digest",
        topics=["chain binding", "sequence freshness binding", "domain separation", "replay protection", "hash collision"],
        probes=[
            "digest construction includes block chainid",
            "digest construction commits to entrypoint address",
            "digest construction commits to operation sequence counter",
            "digest construction commits to operation sender",
            "digest construction commits to full calldata payload",
            "eip-712 domain separation in structured hash calculation",
            "packed encoding multiple dynamic arguments hash collision",
        ],
        date_added="2026-09-01",
    ),

    # 3. entrypoint_digest
    "entrypoint_digest": TriggerEntry(
        mechanism="entrypoint_digest",
        topics=["zero address recovery", "signature malleability", "cross account replay", "magic value return"],
        probes=[
            "ecrecover return value address zero rejection check",
            "signature high s value malleability rejection",
            "signature valid v value range check",
            "cross account signature reuse protection",
            "erc-1271 isvalidsignature magic value return condition",
        ],
        date_added="2026-09-01",
    ),

    # 4. consumed_set
    "consumed_set": TriggerEntry(
        mechanism="consumed_set",
        topics=["single use status", "replay protection", "state invalidation"],
        probes=[
            "single use authorization resource consumption marker",
            "validation phase resource status update check",
            "duplicate submission prevention via consumed state",
        ],
        date_added="2026-09-01",
    ),

    # 5. consumed_set+postop_handler (composite)
    "consumed_set+postop_handler": TriggerEntry(
        mechanism="consumed_set+postop_handler",
        topics=["consumption ordering", "bundle double spend", "validation phase consumption"],
        probes=[
            "coupon marked consumed during validation phase before execution",
            "single use token consumption before postop callback",
            "bundle validation preceding execution ordering constraint",
        ],
        date_added="2026-09-01",
    ),

    # 6. time_bound
    "time_bound": TriggerEntry(
        mechanism="time_bound",
        topics=["validation timestamp", "time window expiry", "validuntil validafter"],
        probes=[
            "packed validation data validuntil and validafter range",
            "timestamp restriction enforcement via validation data return",
            "time window upper and lower bound enforcement",
        ],
        date_added="2026-09-01",
    ),

    # 7. external_call_in_validation
    "external_call_in_validation": TriggerEntry(
        mechanism="external_call_in_validation",
        topics=["validation boundary", "staking", "reputation", "forbidden call target"],
        probes=[
            "external contract call restriction during validation phase",
            "entity deposit and stake verification requirements",
            "reputation tracking and call access restrictions in validation",
        ],
        date_added="2026-09-01",
    ),

    # 8. postop_handler
    "postop_handler": TriggerEntry(
        mechanism="postop_handler",
        topics=["postop revert handling", "postop gas accounting", "postopmode branching"],
        probes=[
            "postop callback handling postopreverted mode without revert",
            "postop gas refund and cost calculation logic",
            "postop state dependence separate from validation logic",
        ],
        date_added="2026-09-01",
    ),

    # 9. webauthn_verifier
    "webauthn_verifier": TriggerEntry(
        mechanism="webauthn_verifier",
        topics=["ceremony type", "challenge binding", "signature range", "low s malleability", "user presence"],
        probes=[
            "clientdatajson type webauthn get assertion verification",
            "clientdatajson challenge hash equality verification",
            "authenticator data and client data hash concatenation order",
            "secp256r1 signature scalar range and low s constraint",
            "authenticator flags user presence and user verification checks",
        ],
        date_added="2026-09-01",
    ),

    # 10. module_installation
    "module_installation": TriggerEntry(
        mechanism="module_installation",
        topics=["type confusion", "attestation", "hook denial of service", "fallback handler", "validator removal"],
        probes=[
            "validator and executor module type differentiation check",
            "module installation attestation and registry verification",
            "hook precheck and postcheck execution without account lockout",
            "fallback handler msg sender context appending standard",
            "prevent uninstalling last active validator module",
        ],
        date_added="2026-09-01",
    ),

    # 11. policy_map
    "policy_map": TriggerEntry(
        mechanism="policy_map",
        topics=["spending limit", "target whitelist", "calldata decoding", "batch element policy"],
        probes=[
            "transfer value spending limit cap enforcement",
            "destination contract address allowlist verification",
            "decoded calldata function selector verification check",
            "batch execution elements individual policy enforcement",
        ],
        date_added="2026-09-01",
    ),
}


def get_topics_and_probes_for_mechanisms(mechanism_tags: List[str]) -> Tuple[List[str], List[str]]:
    """
    Given a list of structural mechanism tags E_mech(c), lookup active topics and search probes.
    """
    active_set = set(mechanism_tags)
    topics: List[str] = []
    probes: List[str] = []

    # Check composite mechanism triggers first
    if "consumed_set" in active_set and "postop_handler" in active_set:
        entry = TRIGGER_MAP.get("consumed_set+postop_handler")
        if entry:
            topics.extend(entry.topics)
            probes.extend(entry.probes)

    for m in mechanism_tags:
        if m in TRIGGER_MAP:
            entry = TRIGGER_MAP[m]
            topics.extend(entry.topics)
            probes.extend(entry.probes)

    # Deduplicate while preserving order
    dedup_topics = list(dict.fromkeys(topics))
    dedup_probes = list(dict.fromkeys(probes))

    return dedup_topics, dedup_probes
