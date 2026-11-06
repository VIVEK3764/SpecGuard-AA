# SPDX-License-Identifier: MIT
"""
Script to link corpus chunks to normative obligations (Step A1).
Performs sentence-level co-occurrence checking between normative modals / defect vocabulary
and obligation terminology sets, enriched with canonical spec mappings, and writes the
linked obligation_ids back to the corpus.
"""

import os
import re
import json
from collections import Counter, defaultdict
from typing import Dict, Set, List, Tuple

# Normative modal regex (for specifications and audit findings)
NORMATIVE_MODALS = re.compile(
    r"\b(must not|must|shall|should|required|forbidden|only if|never)\b",
    re.IGNORECASE
)

# Defect vocabulary (for audit findings)
DEFECT_VOCABULARY = re.compile(
    r"\b(fails to|fail to|does not|doesn't|missing|absent|no check|without verifying|without checking|allows|can be|cannot|may not|vulnerable|bypassed|bypass|unprotected|unrestricted|lack of|drain|replay|replayed|arbitrary|revert|failed|issue|bug|flaw)\b",
    re.IGNORECASE
)

# Canonical rule mappings for ERC-7562 and ERC-4337 chunks
CANONICAL_SPEC_MAPPINGS: Dict[str, List[str]] = {
    "ERC7562-SCOPE-001": ["OP-011", "STO-010"],
    "ERC7562-SCOPE-003": ["OP-011", "STO-010"],
    "ERC7562-SCOPE-005": ["DIG-004", "OP-041"],
    "ERC7562-OP-011": ["OP-011", "OP-012", "OP-013", "OP-020", "OP-041", "OP-051", "OP-052", "OP-053", "OP-054", "OP-055", "OP-061", "OP-062", "OP-070", "OP-080"],
    "ERC7562-COD-010": ["COD-010"],
    "ERC7562-STO-010": ["STO-010", "STO-021", "STO-022", "STO-031", "STO-032", "STO-033"],
    "ERC7562-STO-040": ["STO-040"],
    "ERC7562-EREP-010": ["EREP-050", "EREP-055", "EREP-070"],
    "ERC7562-AUTH-010": ["AUTH-010", "AUTH-020", "AUTH-030", "AUTH-040"],
    "ERC7562-LIM-010": ["LIM-010", "LIM-020", "LIM-030", "LIM-040", "LIM-050"],
    "ERC7562-SCOPE-026": ["OP-011", "OP-012", "OP-013"],
    "ERC7562-SCOPE-027": ["STO-010", "STO-021", "STO-022"],
    "ERC7562-SCOPE-028": ["STO-031", "STO-032", "STO-033"],
    "ERC4337-SPEC-001": ["DIG-004", "DIG-005", "SIG-001"],
    "ERC4337-SPEC-002": ["DIG-003", "DIG-004", "SIG-001"],
    "ERC4337-SPEC-004": ["PAY-001", "PAY-006"],
    "ERC4337-SPEC-007": ["DIG-001", "DIG-002", "DIG-003"],
    "ERC4337-SPEC-008": ["DIG-003"],
    "ERC4337-SPEC-009": ["PAY-001", "PAY-003", "PAY-007"],
    "ERC4337-SPEC-011": ["DIG-001", "DIG-002", "DIG-003", "DIG-004", "DIG-005", "DIG-006", "DIG-007", "PAY-002"],
    "ERC4337-SPEC-013": ["PAY-001", "PAY-005"],
    "ERC4337-SPEC-014": ["PAY-001", "PAY-005", "ORD-004"],
    "ERC4337-SPEC-017": ["PAY-006", "PRE-001", "PRE-002"],
    "ERC4337-SPEC-018": ["PAY-006", "ORD-002"],
    "ERC4337-SPEC-021": ["PAY-001", "PAY-005", "ORD-003"],
}

# Obligation Terminology Sets for all 81 obligations in D1
OBLIGATION_TERMS: Dict[str, Set[str]] = {
    # Session Keys (SES-001 to SES-007)
    "SES-001": {"target", "allowedtarget", "destination", "permitted destination", "target contract", "contract restriction", "permitted target", "target whitelist", "target allowlist", "destination address", "allowed target", "session target", "restricted target"},
    "SES-002": {"selector", "function selector", "allowed selector", "permitted selector", "selector restriction", "selector whitelist", "allowed function", "selector allowlist", "session selector", "permitted function"},
    "SES-003": {"value limit", "msg.value", "spend limit", "transfer limit", "native token limit", "maximum value", "eth limit", "spending limit", "token limit", "max value", "allowance limit", "limit per call"},
    "SES-004": {"expiry", "expiration", "validuntil", "validafter", "validity window", "session expiry", "deadline", "expired", "valid until", "expiration timestamp", "validity period", "time-bound"},
    "SES-005": {"revocation", "revoke", "revoked", "invalidation", "cancel session", "invalidate key", "revoke session", "key revocation", "disabled session", "remove key"},
    "SES-006": {"setsessionkey", "addsessionkey", "session key upgrade", "session key admin", "session key owner", "sessionkey", "session permissions", "unrestricted session", "session key cannot upgrade", "session key install", "delegated key upgrade", "session key change owner", "unrestricted session authority", "delegated signer upgrade", "session key administrative", "delegated authority upgrade", "install another key", "session key privilege", "sessionlib"},
    "SES-007": {"executebatch", "batch execution", "batch elements", "batch call", "inner call", "decoded execution target", "each call in batch", "batch target", "batch transaction", "multicall target", "batch operation", "batch of calls", "batch transactions", "multicall"},

    # Local & EntryPoint Digest Binding (DIG-001 to DIG-008)
    "DIG-001": {"chainid", "cross-chain", "cross chain", "block.chainid", "chain id", "replay across chains", "different chain", "chain replay", "multichain replay"},
    "DIG-002": {"entrypoint", "entry point", "entrypoint address", "trusted entrypoint", "commit to entrypoint", "entrypoint digest", "verifying entrypoint"},
    "DIG-003": {"nonce", "operation replay", "nonce replay", "freshness", "commit to nonce", "sequence number", "replay userop", "replay operation", "userop nonce"},
    "DIG-004": {"commit to sender", "op.sender", "digest sender", "hash sender", "binds sender", "bind sender", "commit to op.sender", "cross-account signature reuse", "include sender in hash", "include op.sender", "hash must include sender", "digest must commit to sender", "binds the sender", "sender in digest", "sender verification in digest", "hash with sender", "userop.sender", "address(sender)", "account address"},
    "DIG-005": {"calldata", "op.calldata", "call data", "execution payload", "commit to calldata", "digest calldata", "hash calldata", "entire calldata", "bind calldata"},
    "DIG-006": {"callgaslimit", "verificationgaslimit", "preverificationgas", "maxfeepergas", "maxpriorityfeepergas", "accountgaslimits", "gasfees", "gas limit", "gas fields in digest", "commit to gas"},
    "DIG-007": {"eip-712", "eip712", "domain separator", "domain separation", "typehash", "structured data hash", "eip 712", "typed data"},
    "DIG-008": {"encodepacked", "abi.encodepacked", "hash collision", "dynamic arguments", "packed encoding", "collision in hash", "abi.encodepacked collision"},

    # Signatures (SIG-001 to SIG-005)
    "SIG-001": {"address(0)", "address zero", "ecrecover zero", "ecrecover", "invalid signer", "zero address recovery", "recovered address 0", "returns address(0)"},
    "SIG-002": {"malleability", "high s", "secp256k1n", "signature malleability", "canonical signature", "canonical s", "malleable", "compact signature malleability"},
    "SIG-003": {"v value", "signature v", "recovery id", "v == 27", "v == 28", "valid v", "invalid v", "v parameter", "v byte"},
    "SIG-004": {"isvalidsignature", "1271", "magic value", "0x1626ba7e", "erc-1271", "erc1271", "eip-1271", "smart contract signature"},
    "SIG-005": {"erc-6492", "erc6492", "6492", "counterfactual signature", "cross-account", "cross account", "signature replay across", "shared-signer", "wallet signature reuse", "signature replay"},

    # Paymasters (PAY-001 to PAY-008)
    "PAY-001": {"validatepaymasteruserop", "paymaster context", "postop context", "context parameter", "context returned", "paymaster's context"},
    "PAY-002": {"paymaster signature", "sponsor signature", "paymaster digest", "sponsor authorization", "paymaster chainid", "sponsor digest", "paymaster replay across chains", "paymaster across chains", "paymaster cross-chain", "cross-chain paymaster"},
    "PAY-003": {"paymaster address", "verifying paymaster", "paymaster validafter", "paymaster validuntil", "paymaster validity", "sponsor validity", "paymaster timestamp", "verifying contract paymaster", "paymaster expiration", "verifyingpaymaster", "address(this) in paymaster"},
    "PAY-004": {"coupon", "usedcoupon", "single-use", "single use", "double-spend", "voucher", "discount", "reimbursement", "coupon replay", "used coupon", "maxcost", "max cost"},
    "PAY-005": {"postop", "postoperation", "postop callback", "revert postop", "postop revert", "postop guarantee", "postopmode", "postop handler", "post-op"},
    "PAY-006": {"paymaster deposit", "entrypoint deposit", "prefund deposit", "sponsor funds", "sponsor deposit", "paymaster balance", "deposit drain", "sufficient deposit", "unbounded sponsorship", "deposit to pay", "drain paymaster", "drain deposit"},
    "PAY-007": {"erc20 paymaster", "token paymaster", "user balance", "token allowance", "token fee", "paymaster token", "erc20 fee", "charge token", "token payment"},
    "PAY-008": {"price oracle", "exchange rate", "stale price", "oracle feed", "token price", "oracle price", "chainlink", "oracle manipulation", "stale oracle", "price feed"},

    # Prefund (PRE-001 to PRE-003)
    "PRE-001": {"missingaccountfunds", "prefund", "payprefund", "entrypoint.call", "deposit to entrypoint", "prefund payment", "required prefund", "account funds"},
    "PRE-002": {"refund", "prefund refund", "excess payment", "unused gas refund", "refund excess", "return value of prefund", "handle prefund return", "excess gas refund", "refund unused"},
    "PRE-003": {"insufficient prefund", "account balance drain", "drain balance", "drain account", "escape payment", "failed validation escape", "drain prefund", "unpaid validation", "avoid prefund", "prefund drain", "prefund", "missingaccountfunds", "account funds"},

    # Ordering & Double-Spend (ORD-001 to ORD-004)
    "ORD-001": {"validation phase consumption", "consume during validation", "consume before execution", "mark consumed in validation", "one-shot resource", "consumed in validation", "state update in validation", "consumed flag", "marked consumed", "consumed", "consume", "double-spend", "validation phase", "one-shot", "single-use"},
    "ORD-002": {"bundle front-running", "mempool front-running", "bundle double-spend", "front-run", "double spend in bundle", "frontrunning", "front-running", "mempool frontrunning", "sandwich"},
    "ORD-003": {"consume in postop", "postop fail allows replay", "postop replay", "written only in postop", "validation depends on postop", "state in postop", "state updated in postop", "written in postop"},
    "ORD-004": {"state invalidation", "sequence invalidation", "state invalidation timing", "postopmode.postopreverted", "branch on mode", "operation succeeded in postop", "postop revert handling", "postopreverted", "refund logic in postop"},

    # WebAuthn / Passkeys (WEB-001 to WEB-006)
    "WEB-001": {"clientdatajson", "client data", "type == webauthn.get", "webauthn.get", "webauthn json", "clientdatajson.type", "registration ceremony", "clientdata", "passkey", "webauthn", "passkeyvalidator", "webauthn protocol", "registration"},
    "WEB-002": {"webauthn challenge", "userophash challenge", "expected challenge", "auth challenge", "clientdatajson.challenge", "challenge matches userophash", "challenge verification", "challenge"},
    "WEB-003": {"secp256r1", "p-256", "p256", "r1 curve", "daimo", "freshcrypto", "rip-7212", "rip7212", "p256 verification", "passkey verification"},
    "WEB-004": {"user presence", "user verification", "up flag", "uv flag", "auth flags", "user presence bit", "psychic signature", "[1, n-1]", "range of r and s", "psychic", "curve order", "secp256k1n", "secp256r1 curve", "r and s"},
    "WEB-005": {"authenticatordata", "rpidhash", "relying party", "relying party id", "low-s", "webauthn malleability", "authenticator data", "rpid", "malleability", "canonical s", "signature malleability", "authenticator"},
    "WEB-006": {"public key coordinates", "x coordinate", "y coordinate", "affine coordinate", "webauthn public key", "p256 public key", "affine point", "uncompressed public key", "public key", "coordinates"},

    # Modules (MOD-001 to MOD-006)
    "MOD-001": {"installmodule", "oninstall", "module installation", "authorized installer", "validator and executor", "module type", "install module"},
    "MOD-002": {"uninstallmodule", "onuninstall", "module uninstallation", "cleanup state", "module removal", "erc-7484", "erc7484", "module attestation", "module allowlist", "registry attestation"},
    "MOD-003": {"executeviamodule", "module execution", "permitted module", "call via module", "execution hook", "brick the account", "hook revert", "brick account", "hook failure", "hook"},
    "MOD-004": {"execution hook", "precheck", "postcheck", "hook check", "fallback handler", "erc-2771", "erc2771", "append original msg.sender", "fallbackhandler", "original msg.sender", "fallback", "fallback function", "staticcall", "module fallback"},
    "MOD-005": {"validator module", "isolated validator", "fallback handler", "validation module", "validator selection", "nonce key validator", "module selection", "untrusted validator"},
    "MOD-006": {"init data", "module init", "module data validation", "module initialization", "uninstalling the last validator", "last validator", "account becomes unrecoverable", "cannot uninstall", "uninstall validator", "uninstall", "module data"},

    # Code Hash (COD-010)
    "COD-010": {"extcodehash", "code hash", "codehash", "contract code", "selfdestruct", "code hash unchanged", "extcodehash value"},

    # Storage Access (STO-010, STO-021, STO-022, STO-031, STO-032, STO-033, STO-040)
    "STO-010": {"storage slot", "account storage", "slot association", "storage access rule", "own storage", "access own storage", "storage access"},
    "STO-021": {"external storage", "staked entity", "stake requirement", "associated storage", "external storage access"},
    "STO-022": {"associated storage", "mapping access during validation", "storage boundary", "initcode factory stake", "factory is staked"},
    "STO-031": {"tload", "tstore", "transient storage", "eip-1153", "staked entity storage", "entity access own storage"},
    "STO-032": {"storage write", "sstore in validation", "validation sstore", "staked entity write", "write associated", "sstore"},
    "STO-033": {"read-only storage", "non-entity storage", "read-only access", "non-entity contract", "read only storage", "read-only"},
    "STO-040": {"storage penalty", "multiple entity roles", "factory and paymaster", "paymaster and account", "serve as an account", "implement both roles", "entity cannot be account"},

    # Opcodes (OP-011, OP-012, OP-013, OP-020, OP-041, OP-051 to OP-055, OP-061, OP-062, OP-070, OP-080)
    "OP-011": {"forbidden opcode", "timestamp in validation", "blockhash", "gasprice", "coinbase", "prevrandao", "basefee", "blocked opcode", "environment opcode", "origin opcode"},
    "OP-012": {"gas opcode", "call opcode", "gas followed by call", "gas opcode immediately", "gasleft in validation", "gas opcode followed by", "gasleft()", "gasleft"},
    "OP-013": {"invalid opcode", "unassigned opcode", "forbidden invalid opcode", "unknown opcode", "invalid instruction"},
    "OP-020": {"out of gas in validation", "validation oof", "out of gas error", "revert with out of gas", "validation out-of-gas", "out-of-gas", "out of gas", "gas exhaustion"},
    "OP-041": {"create2 in validation", "initcode execution", "counterfactual deployment", "no deployed code", "extcode on undeployed", "call undeployed address", "callee codesize", "create2", "initcode"},
    "OP-051": {"extcodesize iszero", "extcodesize", "entrypoint access", "iszero entrypoint"},
    "OP-052": {"depositto", "depositto(sender)", "depositto entrypoint", "deposit to entrypoint"},
    "OP-053": {"entrypoint fallback", "fallback from sender", "fallback to entrypoint", "fallback"},
    "OP-054": {"incrementnonce", "incrementnonce()", "increment nonce from sender", "increment nonce", "increment signonce"},
    "OP-055": {"forbidden call to entrypoint", "entrypoint access during validation", "entrypoint allowlist", "access to entrypoint address", "entrypoint interaction"},
    "OP-061": {"call with value", "msg.value in validation call", "call with non-zero value", "call with value is forbidden", "non-zero call value", "call with value"},
    "OP-062": {"precompile in validation", "allowed precompile", "secp256r1 precompile", "ripemd160", "core precompiles", "0x01 precompile", "precompile range", "precompiles", "precompile"},
    "OP-070": {"transient storage treated as persistent", "tload in validation", "tstore in validation", "transient storage validation", "tload", "tstore", "transient storage"},
    "OP-080": {"balance opcode in validation", "selfbalance in validation", "balance of staked entity", "balance opcode", "selfbalance opcode", "selfbalance"},

    # Authorization
    "AUTH-010": {"authorization tuple", "mempool authorization", "authorization count", "single authorization", "7702 tuple"},
    "AUTH-020": {"7702 delegation", "eip-7702 sender", "delegated account sender", "7702", "eip-7702", "delegated account"},
    "AUTH-030": {"authorization tuple signature", "7702 signature", "delegation signature", "delegated account accessed", "access delegated account"},
    "AUTH-040": {"bundler authority tracking", "bundler authority", "track bundler authority"},

    # Entity Reputation
    "EREP-050": {"unstaked paymaster context", "unstaked context", "paymaster reputation", "unstaked paymaster", "context without stake", "paymaster stake"},
    "EREP-055": {"context size stability", "context length change", "paymaster context size", "context length", "context size change", "context size", "context bytes"},
    "EREP-070": {"validation gas reduction", "gas reduction limit", "entity stake", "reduce validation gas", "gas reduction between validation", "stake requirement", "staked entity"},

    # Limits
    "LIM-010": {"verificationgaslimit ceiling", "validation gas limit", "max_userop_size", "useroperation size limit"},
    "LIM-020": {"max_context_size", "context size limit", "2048 bytes context", "max context size", "context byte array"},
    "LIM-030": {"validation_gas_safety_margin", "validation safety margin", "10000 gas margin", "validation_gas_slack", "gas slack"},
    "LIM-040": {"calldata size limit", "payload length limit", "calldata limit", "maximum calldata size", "calldata size"},
    "LIM-050": {"max priority fee ceiling", "priority fee limit", "priority fee ceiling", "maxfeepergas ceiling", "priority fee"},
}


def split_sentences(text: str) -> List[str]:
    """Splits text into sentences while respecting markdown and code blocks."""
    raw_sentences = re.split(r"(?:(?<=[.!?])\s+|\n+)", text)
    sentences = [s.strip() for s in raw_sentences if s.strip()]
    return sentences


def link_chunk_to_obligations(chunk: dict, is_spec: bool = False) -> List[str]:
    """
    Evaluates sentence-level co-occurrence between normative modals / defect vocabulary
    and obligation terms. Canonical spec chunks also map directly.
    """
    text = chunk.get("text", "")
    chunk_id = chunk.get("id", "")
    sentences = split_sentences(text)

    matched_obligations: Set[str] = set()

    # 1. Direct canonical specification mapping
    if chunk_id in CANONICAL_SPEC_MAPPINGS:
        matched_obligations.update(CANONICAL_SPEC_MAPPINGS[chunk_id])

    for oid in OBLIGATION_TERMS.keys():
        if oid in chunk_id or f"[{oid}]" in text:
            matched_obligations.add(oid)

    # 2. Sentence-level modal/defect co-occurrence
    for sentence in sentences:
        s_lower = sentence.lower()
        if is_spec:
            if not NORMATIVE_MODALS.search(s_lower):
                continue
        else:
            if not (NORMATIVE_MODALS.search(s_lower) or DEFECT_VOCABULARY.search(s_lower)):
                continue

        for oid, terms in OBLIGATION_TERMS.items():
            for term in terms:
                if term in s_lower:
                    matched_obligations.add(oid)
                    break

    return sorted(list(matched_obligations))


def process_corpus_file(file_path: str, is_spec: bool = False) -> Tuple[List[dict], List[str]]:
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return [], []

    with open(file_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    populated_count = 0
    all_matched_oids = []

    for c in chunks:
        oids = link_chunk_to_obligations(c, is_spec=is_spec)
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

    audit_chunks, audit_oids = process_corpus_file("corpus/audit_knowledge.json", is_spec=False)
    erc4337_chunks, erc4337_oids = process_corpus_file("corpus/erc4337.json", is_spec=True)
    erc7562_chunks, erc7562_oids = process_corpus_file("corpus/erc7562.json", is_spec=True)

    all_chunks = audit_chunks + erc4337_chunks + erc7562_chunks
    total_chunks = len(all_chunks)
    total_populated = sum(1 for c in all_chunks if c.get("obligation_ids"))

    all_counter = Counter(o for ch in all_chunks for o in ch.get("obligation_ids", []))
    total_links = sum(all_counter.values())

    print("\n" + "=" * 70)
    print("STEP A1 DISTRIBUTION AND ROBUSTNESS VERIFICATION")
    print("=" * 70)
    print(f"Total chunks in corpus: {total_chunks}")
    print(f"Chunks with >= 1 obligation ID: {total_populated} ({total_populated/total_chunks*100:.2f}%)")
    print(f"Obligations covered: {len(all_counter)} / {len(OBLIGATION_TERMS)} (target >= 70)")
    print(f"Total link instances: {total_links}")

    if all_counter:
        max_oid, max_count = all_counter.most_common(1)[0]
        max_pct = max_count / float(total_links) * 100
        print(f"Max link concentration: {max_oid} holds {max_count} links ({max_pct:.2f}% of all links, target <= 15.0%)")

    # Family-by-family coverage
    d1_path = "corpus/phase_d/d1_labels_ALL.json"
    if os.path.exists(d1_path):
        with open(d1_path, "r", encoding="utf-8") as f:
            d1_data = json.load(f)
        all_d1_obligations = sorted(list(d1_data["contracts"][0]["labels"].keys()))
    else:
        all_d1_obligations = sorted(list(OBLIGATION_TERMS.keys()))

    family_stats = defaultdict(lambda: {"total": 0, "covered": 0})
    for oid in all_d1_obligations:
        fam = oid.split("-")[0]
        family_stats[fam]["total"] += 1
        if oid in all_counter:
            family_stats[fam]["covered"] += 1

    print("\n" + "-" * 70)
    print("COVERAGE PER OBLIGATION FAMILY:")
    print("-" * 70)
    print(f"{'Family':<8} | {'Covered':<8} | {'Total':<6} | {'Coverage %':<10}")
    print("-" * 70)
    for fam in sorted(family_stats.keys()):
        cov = family_stats[fam]["covered"]
        tot = family_stats[fam]["total"]
        pct = cov / float(tot) * 100.0 if tot > 0 else 0.0
        print(f"{fam:<8} | {cov:<8} | {tot:<6} | {pct:>8.1f}%")

    uncovered = [oid for oid in all_d1_obligations if oid not in all_counter]
    if uncovered:
        print(f"\nUncovered obligations ({len(uncovered)}): {uncovered}")
    else:
        print(f"\nAll {len(all_d1_obligations)} obligations successfully covered with >=1 chunk!")


if __name__ == "__main__":
    main()
