# SPDX-License-Identifier: MIT
"""
Version Scoping Heuristics Engine for SpecGuard-AA (Step A3).
Applies deterministic version scoping across corpus chunks based on EntryPoint protocol markers:
- Explicit version strings: v0.6, v0.7, 0.6.0, 0.7.0, EntryPoint 0.6, EntryPoint 0.7, EIP-7702, v0.8
- Field names:
  - callGasLimit and verificationGasLimit as separate fields imply v0.6
  - accountGasLimits, gasFees, paymasterVerificationGasLimit, postOpGasLimit imply v0.7+
- Paymaster prefix: 20-byte paymasterAndData prefix (v0.6) vs 52-byte prefix (v0.7+)
- Deployment fields: initCode (v0.6) vs factory / factoryData (v0.7+)
- Weak contest/audit date prior: 2022/2023 predate EntryPoint v0.7 release (March 2024)
"""

import os
import re
import json
from collections import Counter
from typing import Dict, List, Tuple


V06_EXPLICIT = re.compile(
    r"\b(v0\.6|0\.6\.0|v0\.6\.0|EntryPoint\s*0\.6|entrypoint\s*v0\.6)\b",
    re.IGNORECASE
)

V07_EXPLICIT = re.compile(
    r"\b(v0\.7|0\.7\.0|v0\.7\.0|EntryPoint\s*0\.7|entrypoint\s*v0\.7)\b",
    re.IGNORECASE
)

V08_EXPLICIT = re.compile(
    r"\b(v0\.8|0\.8\.0|v0\.8\.0|EntryPoint\s*0\.8|entrypoint\s*v0\.8|EIP-?7702|Simple7702Account)\b",
    re.IGNORECASE
)

V06_FIELDS = re.compile(
    r"\b(callGasLimit\s+and\s+verificationGasLimit|verificationGasLimit|callGasLimit|initCode\b(?!.*factoryData)|20[\s-]byte\s+paymasterAndData|20[\s-]byte\s+prefix)\b",
    re.IGNORECASE
)

V07_FIELDS = re.compile(
    r"\b(PackedUserOperation|accountGasLimits|gasFees|paymasterVerificationGasLimit|postOpGasLimit|factoryData|52[\s-]byte\s+paymasterAndData|52[\s-]byte\s+prefix)\b",
    re.IGNORECASE
)

DATE_2023_PRIOR = re.compile(r"\b202[23][\-_]", re.IGNORECASE)
DATE_2024_PLUS_PRIOR = re.compile(r"\b202[456][\-_]", re.IGNORECASE)


def determine_version_scope(text: str, source: str = "") -> Tuple[List[str], bool, str]:
    """
    Returns (version_scope, version_uncertain, rule_applied)
    """
    full_str = f"{source} {text}"

    # 1. Explicit version strings
    has_v08 = bool(V08_EXPLICIT.search(full_str))
    has_v07 = bool(V07_EXPLICIT.search(full_str) or V07_FIELDS.search(text))
    has_v06 = bool(V06_EXPLICIT.search(full_str))

    # 2. Field-level discriminators
    if not (has_v08 or has_v07 or has_v06):
        if "accountGasLimits" in text or "PackedUserOperation" in text or "factoryData" in text:
            has_v07 = True
        elif ("callGasLimit" in text and "verificationGasLimit" in text) or "initCode" in text:
            has_v06 = True

    # 3. Weak prior from contest/audit dates for Account Abstraction chunks
    is_aa_chunk = any(k in full_str.lower() for k in [
        "entrypoint", "useroperation", "userop", "paymaster", "biconomy",
        "kernel", "zerodev", "sessionkey", "simpleaccount"
    ])
    if not (has_v08 or has_v07 or has_v06) and is_aa_chunk:
        if DATE_2023_PRIOR.search(source):
            has_v06 = True
        elif DATE_2024_PLUS_PRIOR.search(source):
            has_v07 = True

    # Deterministic assignment
    if has_v08 and not has_v06 and not has_v07:
        return ["0.8"], False, "v0.8 exclusive (EIP-7702/v0.8)"

    if has_v07 and not has_v06:
        return ["0.7", "0.8"], False, "v0.7/v0.8 (PackedUserOp/accountGasLimits/v0.7)"

    if has_v06 and not has_v07 and not has_v08:
        return ["0.6"], False, "v0.6 (Unpacked/v0.6/2023-prior)"

    if (has_v06 and has_v07) or (has_v06 and has_v08):
        return ["0.6", "0.7", "0.8"], True, "cross-version comparison"

    return ["0.6", "0.7", "0.8"], True, "unscoped / version-independent"


def process_file(file_path: str):
    if not os.path.exists(file_path):
        return [], Counter()

    with open(file_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    rule_counts = Counter()
    scope_counts = Counter()

    for c in chunks:
        scope, uncertain, rule = determine_version_scope(c.get("text", ""), c.get("source", ""))
        c["version_scope"] = scope
        c["version_uncertain"] = uncertain
        rule_counts[rule] += 1
        scope_counts[",".join(scope)] += 1

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2)

    print(f"\n[+] Scoped {file_path} ({len(chunks)} chunks):")
    for rule, count in rule_counts.most_common():
        pct = (count / len(chunks)) * 100
        print(f"  {rule:<45}: {count:4d} ({pct:5.1f}%)")

    return chunks, rule_counts


def main():
    print("=" * 70)
    print("STEP A3: PROTOCOL VERSION SCOPING HEURISTICS")
    print("=" * 70)

    audit_chunks, audit_rules = process_file("corpus/audit_knowledge.json")
    erc4337_chunks, erc4337_rules = process_file("corpus/erc4337.json")
    erc7562_chunks, erc7562_rules = process_file("corpus/erc7562.json")

    all_chunks = audit_chunks + erc4337_chunks + erc7562_chunks
    total_chunks = len(all_chunks)
    scoped_deterministic = sum(1 for c in all_chunks if not c.get("version_uncertain"))
    scoped_pct = (scoped_deterministic / float(total_chunks)) * 100.0 if total_chunks else 0.0

    print("\n" + "=" * 70)
    print("TOTAL CORPUS VERSION SCOPING SUMMARY:")
    print("=" * 70)
    print(f"Total Chunks: {total_chunks}")
    print(f"Deterministically Scoped: {scoped_deterministic} ({scoped_pct:.2f}%)")
    print(f"Version-Uncertain / Broad: {total_chunks - scoped_deterministic} ({100.0 - scoped_pct:.2f}%)")

    if scoped_pct < 20.0:
        print("\n[FINDING]: Scoped fraction is under 20% across the full corpus.")
        print("Conclusion: Version scoping cannot function as a reliable hard filter;")
        print("SpecGuard-AA treats the environment view as a soft prior rather than a hard exclusionary filter.")


if __name__ == "__main__":
    main()
