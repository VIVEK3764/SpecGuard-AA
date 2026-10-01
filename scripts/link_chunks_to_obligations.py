# SPDX-License-Identifier: MIT
"""
Script to link corpus chunks to normative obligations (Step A1).
Performs sentence-level co-occurrence checking between normative modals and
obligation terminology sets, writing the enriched obligation_ids back to the corpus.
"""

import os
import re
import json
from collections import Counter
from typing import Dict, Set, List

# Normative modal regex (Step A1 requirement)
NORMATIVE_MODALS = re.compile(
    r"\b(must not|must|shall|should|required|forbidden|only if|never)\b",
    re.IGNORECASE
)

# Obligation Terminology Sets for all 81 obligations in D1
OBLIGATION_TERMS: Dict[str, Set[str]] = {
    # Session Keys (SES-001 to SES-007)
    "SES-001": {"target", "allowedtarget", "destination", "permitted destination", "target contract", "contract restriction", "permitted target", "target whitelist", "target allowlist", "destination address"},
    "SES-002": {"selector", "function selector", "allowed selector", "permitted selector", "selector restriction", "selector whitelist", "allowed function"},
    "SES-003": {"value limit", "msg.value", "spend limit", "transfer limit", "native token limit", "maximum value", "eth limit"},
    "SES-004": {"expiry", "expiration", "validuntil", "validafter", "validity window", "session expiry", "deadline", "expired", "valid until", "expiration timestamp"},
    "SES-005": {"revocation", "revoke", "revoked", "invalidation", "cancel session", "invalidate key", "revoke session"},
    "SES-006": {"administrative", "admin", "upgrade", "owner action", "setsessionkey", "addsessionkey", "unrestricted authority", "admin function", "account upgrade"},
    "SES-007": {"session key", "session signer", "delegated key", "session authorization", "session signature", "delegated signer"},

    # Local & EntryPoint Digest Binding (DIG-001 to DIG-008)
    "DIG-001": {"chainid", "cross-chain", "cross chain", "block.chainid", "chain id", "replay across chains"},
    "DIG-002": {"entrypoint", "entry point", "entrypoint address", "trusted entrypoint", "commit to entrypoint"},
    "DIG-003": {"nonce", "operation replay", "nonce replay", "freshness", "commit to nonce", "sequence number"},
    "DIG-004": {"sender", "op.sender", "account address", "signature theft", "cross-account", "commit to sender"},
    "DIG-005": {"calldata", "op.calldata", "call data", "execution payload", "commit to calldata"},
    "DIG-006": {"callgaslimit", "verificationgaslimit", "preverificationgas", "maxfeepergas", "maxpriorityfeepergas", "accountgaslimits", "gasfees", "gas limit"},
    "DIG-007": {"eip-712", "eip712", "domain separator", "domain separation", "typehash", "structured data hash"},
    "DIG-008": {"encodepacked", "abi.encodepacked", "hash collision", "dynamic arguments", "packed encoding"},

    # Signatures (SIG-001 to SIG-005)
    "SIG-001": {"address(0)", "address zero", "ecrecover zero", "ecrecover", "invalid signer", "zero address recovery"},
    "SIG-002": {"malleability", "high s", "secp256k1n", "signature malleability", "canonical signature", "canonical s"},
    "SIG-003": {"v value", "signature v", "recovery id", "v == 27", "v == 28", "valid v"},
    "SIG-004": {"isvalidsignature", "1271", "magic value", "0x1626ba7e", "erc-1271", "erc1271"},
    "SIG-005": {"cross-account", "cross account", "signature reuse", "unauthorized reuse", "reuse across accounts"},

    # Paymasters (PAY-001 to PAY-008)
    "PAY-001": {"validatepaymasteruserop", "paymaster context", "postop context", "context parameter"},
    "PAY-002": {"paymaster signature", "sponsor signature", "paymaster digest", "sponsor authorization"},
    "PAY-003": {"paymaster validuntil", "paymaster validafter", "paymaster timestamp", "paymaster validity", "sponsor validity"},
    "PAY-004": {"coupon", "usedcoupon", "single-use", "single use", "double-spend", "voucher", "discount", "reimbursement", "coupon replay"},
    "PAY-005": {"postop", "postoperation", "postop callback", "revert postop", "postop revert", "postop guarantee"},
    "PAY-006": {"paymaster deposit", "entrypoint deposit", "prefund deposit", "sponsor funds", "sponsor deposit"},
    "PAY-007": {"erc20 paymaster", "token paymaster", "user balance", "token allowance", "token fee", "paymaster token"},
    "PAY-008": {"price oracle", "exchange rate", "stale price", "oracle feed", "token price", "oracle price"},

    # Prefund (PRE-001 to PRE-003)
    "PRE-001": {"missingaccountfunds", "prefund", "payprefund", "entrypoint.call", "deposit to entrypoint", "prefund payment"},
    "PRE-002": {"refund", "prefund refund", "excess payment", "unused gas refund", "refund excess"},
    "PRE-003": {"insufficient prefund", "account balance drain", "drain balance", "drain account"},

    # Ordering & Double-Spend (ORD-001 to ORD-004)
    "ORD-001": {"validation phase consumption", "consume during validation", "consume before execution", "mark consumed in validation"},
    "ORD-002": {"bundle front-running", "mempool front-running", "bundle double-spend", "front-run", "double spend in bundle"},
    "ORD-003": {"consume in postop", "postop fail allows replay", "postop replay"},
    "ORD-004": {"state invalidation", "sequence invalidation", "state invalidation timing"},

    # WebAuthn / Passkeys (WEB-001 to WEB-006)
    "WEB-001": {"clientdatajson", "client data", "type == webauthn.get", "webauthn.get", "webauthn json"},
    "WEB-002": {"webauthn challenge", "userophash challenge", "expected challenge", "auth challenge"},
    "WEB-003": {"secp256r1", "p-256", "p256", "r1 curve", "daimo", "freshcrypto"},
    "WEB-004": {"user presence", "user verification", "up flag", "uv flag", "auth flags", "user presence bit"},
    "WEB-005": {"authenticatordata", "rpidhash", "relying party", "relying party id"},
    "WEB-006": {"public key coordinates", "x coordinate", "y coordinate", "affine coordinate"},

    # Modules (MOD-001 to MOD-006)
    "MOD-001": {"installmodule", "oninstall", "module installation", "authorized installer"},
    "MOD-002": {"uninstallmodule", "onuninstall", "module uninstallation", "cleanup state", "module removal"},
    "MOD-003": {"executeviamodule", "module execution", "permitted module", "call via module"},
    "MOD-004": {"execution hook", "precheck", "postcheck", "hook check"},
    "MOD-005": {"validator module", "isolated validator", "fallback handler", "validation module"},
    "MOD-006": {"init data", "module init", "module data validation", "module initialization"},

    # Code Hash (COD-010)
    "COD-010": {"extcodehash", "code hash", "codehash", "contract code", "selfdestruct"},

    # Storage Access (STO-010, STO-021, STO-022, STO-031, STO-032, STO-033, STO-040)
    "STO-010": {"storage slot", "account storage", "slot association", "storage access rule"},
    "STO-021": {"external storage", "staked entity", "stake requirement"},
    "STO-022": {"associated storage", "mapping access during validation", "storage boundary"},
    "STO-031": {"tload", "tstore", "transient storage", "eip-1153"},
    "STO-032": {"storage write", "sstore in validation", "validation sstore"},
    "STO-033": {"read-only storage", "non-entity storage"},
    "STO-040": {"storage penalty", "multiple entity roles", "factory and paymaster", "paymaster and account"},

    # Opcodes (OP-011, OP-012, OP-013, OP-020, OP-041, OP-051 to OP-055, OP-061, OP-062, OP-070, OP-080)
    "OP-011": {"forbidden opcode", "timestamp in validation", "blockhash", "gasprice", "coinbase", "prevrandao", "basefee"},
    "OP-012": {"gas opcode", "call opcode", "gas followed by call"},
    "OP-013": {"invalid opcode", "unassigned opcode"},
    "OP-020": {"out of gas in validation", "validation oof", "out of gas error"},
    "OP-041": {"create2 in validation", "initcode execution", "counterfactual deployment"},
    "OP-051": {"call opcode in validation", "extcall in validation"},
    "OP-052": {"delegatecall in validation", "untrusted delegatecall"},
    "OP-053": {"callcode in validation"},
    "OP-054": {"staticcall in validation"},
    "OP-055": {"selfdestruct in validation"},
    "OP-061": {"call with value", "msg.value in validation call", "call with non-zero value"},
    "OP-062": {"precompile in validation", "allowed precompile", "secp256r1 precompile", "ripemd160"},
    "OP-070": {"transient storage treated as persistent", "tload in validation"},
    "OP-080": {"balance opcode in validation", "selfbalance in validation", "balance of staked entity"},

    # Authorization tuples / EIP-7702 (AUTH-010 to AUTH-040)
    "AUTH-010": {"authorization tuple", "mempool authorization", "authorization count"},
    "AUTH-020": {"7702 delegation", "eip-7702 sender", "delegated account sender", "7702"},
    "AUTH-030": {"authorization tuple signature", "7702 signature", "delegation signature"},
    "AUTH-040": {"bundler authority tracking", "bundler authority"},

    # Entity Reputation (EREP-050, EREP-055, EREP-070)
    "EREP-050": {"unstaked paymaster context", "unstaked context", "paymaster reputation"},
    "EREP-055": {"context size stability", "context length change", "paymaster context size"},
    "EREP-070": {"validation gas reduction", "gas reduction limit", "entity stake"},

    # Limits (LIM-010 to LIM-050)
    "LIM-010": {"verificationgaslimit ceiling", "validation gas limit"},
    "LIM-020": {"max_context_size", "context size limit", "2048 bytes context"},
    "LIM-030": {"validation_gas_safety_margin", "validation safety margin", "10000 gas margin"},
    "LIM-040": {"calldata size limit", "payload length limit"},
    "LIM-050": {"max priority fee ceiling", "priority fee limit"},
}


def split_sentences(text: str) -> List[str]:
    """Splits text into sentences while respecting markdown and code blocks."""
    raw_sentences = re.split(r"(?:(?<=[.!?])\s+|\n+)", text)
    sentences = [s.strip() for s in raw_sentences if s.strip()]
    return sentences


def link_chunk_to_obligations(chunk: dict) -> List[str]:
    """
    Evaluates sentence-level co-occurrence between normative modals and obligation terms.
    Returns matched obligation IDs.
    """
    text = chunk.get("text", "")
    chunk_id = chunk.get("id", "")
    sentences = split_sentences(text)

    matched_obligations: Set[str] = set()

    # Direct canonical specification mapping: e.g. ERC7562-AUTH-010 -> AUTH-010, [AUTH-020] in text
    for oid in OBLIGATION_TERMS.keys():
        if oid in chunk_id or f"[{oid}]" in text:
            matched_obligations.add(oid)

    for sentence in sentences:
        s_lower = sentence.lower()
        if not NORMATIVE_MODALS.search(s_lower):
            continue

        for oid, terms in OBLIGATION_TERMS.items():
            for term in terms:
                if term in s_lower:
                    matched_obligations.add(oid)
                    break

    return sorted(list(matched_obligations))


def process_corpus_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return [], []

    with open(file_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    populated_count = 0
    all_matched_oids = []

    for c in chunks:
        oids = link_chunk_to_obligations(c)
        c["obligation_ids"] = oids
        if oids:
            populated_count += 1
            all_matched_oids.extend(oids)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2)

    print(f"[+] Processed {file_path}: {populated_count} of {len(chunks)} chunks have >= 1 obligation ID.")
    return chunks, all_matched_oids


def main():
    print("=" * 70)
    print("STEP A1: POPULATING OBLIGATION_IDS ACROSS CORPUS")
    print("=" * 70)

    audit_chunks, audit_oids = process_corpus_file("corpus/audit_knowledge.json")
    erc4337_chunks, erc4337_oids = process_corpus_file("corpus/erc4337.json")
    erc7562_chunks, erc7562_oids = process_corpus_file("corpus/erc7562.json")

    total_chunks = len(audit_chunks) + len(erc4337_chunks) + len(erc7562_chunks)
    total_populated = (
        sum(1 for c in audit_chunks if c.get("obligation_ids")) +
        sum(1 for c in erc4337_chunks if c.get("obligation_ids")) +
        sum(1 for c in erc7562_chunks if c.get("obligation_ids"))
    )

    print("\n" + "-" * 70)
    print("AUDIT_KNOWLEDGE DISTRIBUTION CHECK (Per Prompt Specification):")
    print("-" * 70)
    audit_counter = Counter(o for ch in audit_chunks for o in ch.get("obligation_ids", []))
    print(f"chunks with >=1 id: {sum(1 for c in audit_chunks if c.get('obligation_ids'))}")
    print(f"obligations with >=1 chunk: {len(audit_counter)}")
    print("\nTop 25 most common obligations in audit knowledge:")
    for o, n in audit_counter.most_common(25):
        print(f"  {o:<12}: {n}")

    unmatched_d1_obligations = [oid for oid in OBLIGATION_TERMS.keys() if oid not in audit_counter]
    print(f"\nObligations with zero audit knowledge chunks: {len(unmatched_d1_obligations)}")
    if unmatched_d1_obligations:
        print(f"Zero-coverage obligations in audit corpus: {unmatched_d1_obligations}")


if __name__ == "__main__":
    main()
