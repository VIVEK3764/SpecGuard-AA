# SPDX-License-Identifier: MIT
"""
Version Scoping Heuristics Engine for SpecGuard-AA (Step A3).
Applies deterministic version scoping across corpus chunks based on EntryPoint protocol markers:
- v0.6: UserOperation (unpacked), callGasLimit/verificationGasLimit separate, 20-byte paymasterAndData prefix
- v0.7/0.8: PackedUserOperation, accountGasLimits, gasFees, paymasterVerificationGasLimit, 52-byte prefix
- v0.8: EIP-7702 delegation tuples, Simple7702Account
"""

import os
import re
import json
from collections import Counter
from typing import Dict, List, Tuple


V06_PATTERNS = [
    re.compile(r"\bUserOperation\b"),
    re.compile(r"\bcallGasLimit\b"),
    re.compile(r"\bverificationGasLimit\b"),
    re.compile(r"\bpreVerificationGas\b"),
    re.compile(r"\bmaxFeePerGas\b"),
    re.compile(r"\bmaxPriorityFeePerGas\b"),
    re.compile(r"20[\s-]byte", re.IGNORECASE),
]

V07_PATTERNS = [
    re.compile(r"\bPackedUserOperation\b"),
    re.compile(r"\baccountGasLimits\b"),
    re.compile(r"\bgasFees\b"),
    re.compile(r"\bpaymasterVerificationGasLimit\b"),
    re.compile(r"\bpostOpGasLimit\b"),
    re.compile(r"52[\s-]byte", re.IGNORECASE),
]

V08_PATTERNS = [
    re.compile(r"\bEIP-?7702\b", re.IGNORECASE),
    re.compile(r"delegation tuple", re.IGNORECASE),
    re.compile(r"delegation designation", re.IGNORECASE),
    re.compile(r"\bSimple7702Account\b"),
]


def determine_version_scope(text: str) -> Tuple[List[str], bool, str]:
    """
    Returns (version_scope, version_uncertain, rule_applied)
    """
    has_v08 = any(p.search(text) for p in V08_PATTERNS)
    has_v07 = any(p.search(text) for p in V07_PATTERNS)
    has_v06 = any(p.search(text) for p in V06_PATTERNS)

    if has_v08 and not has_v06 and not has_v07:
        return ["0.8"], False, "v0.8 (EIP-7702 exclusive)"

    if has_v07 and not has_v06:
        return ["0.7", "0.8"], False, "v0.7/v0.8 (PackedUserOperation)"

    if has_v06 and not has_v07 and not has_v08:
        return ["0.6"], False, "v0.6 (Unpacked UserOperation)"

    # If mixed (mentions both migration or comparison) or neither
    if has_v06 and (has_v07 or has_v08):
        return ["0.6", "0.7", "0.8"], True, "cross-version comparison"

    return ["0.6", "0.7", "0.8"], True, "unscoped / version-independent"


def process_file(file_path: str):
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    rule_counts = Counter()
    scope_counts = Counter()

    for c in chunks:
        scope, uncertain, rule = determine_version_scope(c.get("text", ""))
        c["version_scope"] = scope
        c["version_uncertain"] = uncertain
        rule_counts[rule] += 1
        scope_counts[",".join(scope)] += 1

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2)

    print(f"\n[+] Scoped {file_path} ({len(chunks)} chunks):")
    for rule, count in rule_counts.most_common():
        pct = (count / len(chunks)) * 100
        print(f"  {rule:<35}: {count:4d} ({pct:5.1f}%)")

    return chunks, rule_counts


def main():
    print("=" * 70)
    print("STEP A3: PROTOCOL VERSION SCOPING HEURISTICS")
    print("=" * 70)

    audit_chunks, audit_rules = process_file("corpus/audit_knowledge.json")
    erc4337_chunks, erc4337_rules = process_file("corpus/erc4337.json")
    erc7562_chunks, erc7562_rules = process_file("corpus/erc7562.json")

    total_chunks = len(audit_chunks) + len(erc4337_chunks) + len(erc7562_chunks)
    scoped_deterministic = (
        sum(1 for c in audit_chunks if not c.get("version_uncertain")) +
        sum(1 for c in erc4337_chunks if not c.get("version_uncertain")) +
        sum(1 for c in erc7562_chunks if not c.get("version_uncertain"))
    )

    print("\n" + "=" * 70)
    print(f"TOTAL CORPUS VERSION SCOPING SUMMARY:")
    print("=" * 70)
    print(f"Total Chunks: {total_chunks}")
    print(f"Deterministically Scoped: {scoped_deterministic} ({scoped_deterministic/total_chunks*100:.2f}%)")
    print(f"Version-Uncertain / Broad: {total_chunks - scoped_deterministic} ({(total_chunks - scoped_deterministic)/total_chunks*100:.2f}%)")


if __name__ == "__main__":
    main()
