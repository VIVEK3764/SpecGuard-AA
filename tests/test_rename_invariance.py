# SPDX-License-Identifier: MIT
"""
Rename-Invariance Regression Harness for SpecGuard-AA (Step A4).
Verifies that mechanism extraction E_mech(c) and property selection are strictly
structural and completely invariant under variable and internal function renaming.
"""

import os
import re
import glob
import tempfile
import pytest

from specguard.extractor import extract_facts
from specguard.synthesis.synthesizer import PropertySynthesizer
from specguard.binding.binder import NormalizerAndBinder


INTERFACE_RESERVED = {
    # Standard entrypoints & interface functions
    "validateUserOp",
    "validatePaymasterUserOp",
    "postOp",
    "execute",
    "executeViaModule",
    "initialize",
    "createAccount",
    "getAddress",
    "onInstall",
    "onUninstall",
    "installModule",
    "uninstallModule",
    "diamondStorage",
    "entryPoint",
    "ENTRY_POINT",
    "PackedUserOperation",
    "UserOp",
    "ValidationData",
}


def _create_renamed_contract(original_sol_path: str, scratch_dir: str) -> str:
    """
    Produce a deterministically renamed copy of a Solidity contract file.
    Renames state variables and non-interface helper functions.
    Interface functions (e.g. validateUserOp) and protocol types remain untouched.
    """
    os.makedirs(scratch_dir, exist_ok=True)
    with open(original_sol_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find contract name (at start of line to avoid docstring matches)
    contract_match = re.search(r"^\s*contract\s+([A-Za-z0-9_]+)", content, re.MULTILINE)
    if not contract_match:
        raise ValueError(f"No contract definition found in {original_sol_path}")
    orig_contract_name = contract_match.group(1)
    renamed_contract_name = f"Renamed_{orig_contract_name}"

    # Rename contract declaration
    content = content.replace(f"contract {orig_contract_name}", f"contract {renamed_contract_name}")

    # Find state variables (simple regex declaration finder)
    state_var_pattern = r"(address|mapping\([^)]+\)|uint\d*|bytes\d*|bool)\s+(public|private|internal|immutable)?\s*([a-zA-Z0-9_]+)\s*;"
    matches = re.findall(state_var_pattern, content)

    var_map = {}
    var_idx = 0
    for var_type, vis, var_name in matches:
        if var_name not in INTERFACE_RESERVED and not var_name.isupper():
            if var_name not in var_map:
                var_map[var_name] = f"sv_{var_idx}"
                var_idx += 1

    # Find non-interface internal/public helper functions
    fn_pattern = r"function\s+([a-zA-Z0-9_]+)\s*\("
    fn_matches = re.findall(fn_pattern, content)
    fn_map = {}
    fn_idx = 0
    for fn_name in fn_matches:
        if fn_name not in INTERFACE_RESERVED and not fn_name.startswith("_"):
            if fn_name not in fn_map:
                fn_map[fn_name] = f"fn_{fn_idx}"
                fn_idx += 1

    # Apply renamings (longer names first to avoid prefix collision)
    all_renames = {**var_map, **fn_map}
    sorted_keys = sorted(all_renames.keys(), key=len, reverse=True)

    for old_name in sorted_keys:
        new_name = all_renames[old_name]
        # Replace identifier bound by non-word characters
        content = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, content)

    renamed_file_path = os.path.join(scratch_dir, f"{renamed_contract_name}.sol")
    with open(renamed_file_path, "w", encoding="utf-8") as f:
        f.write(content)

    return renamed_file_path, renamed_contract_name


BENCHMARK_CONTRACTS = glob.glob("benchmark/stage1_fact_extraction/contracts/*.sol")


@pytest.mark.rename_invariance
@pytest.mark.parametrize("sol_path", BENCHMARK_CONTRACTS)
def test_rename_invariance_mechanism_tags(sol_path: str):
    """
    Assert that structural mechanism extraction tags E_mech(c) are 100% identical
    between original benchmark contracts and their renamed counterparts.
    """
    if not os.path.exists(sol_path):
        pytest.skip(f"Benchmark file not found: {sol_path}")

    orig_facts = extract_facts(sol_path)

    scratch_dir = os.path.abspath("scratch/renamed_contracts")
    renamed_path, renamed_name = _create_renamed_contract(sol_path, scratch_dir)
    renamed_facts = extract_facts(renamed_path, target_contract_name=renamed_name)

    orig_tags = sorted([t.tag for t in orig_facts.mechanism_tags])
    renamed_tags = sorted([t.tag for t in renamed_facts.mechanism_tags])

    assert orig_tags == renamed_tags, (
        f"Rename-invariance FAILED for {os.path.basename(sol_path)}!\n"
        f"Original tags: {orig_tags}\n"
        f"Renamed tags:  {renamed_tags}\n"
        f"Extraction is relying on variable/function names instead of structural IR."
    )


@pytest.mark.rename_invariance
@pytest.mark.parametrize("sol_path", [
    "benchmark/stage1_fact_extraction/contracts/SessionAccount.sol",
    "benchmark/stage1_fact_extraction/contracts/CouponPaymaster.sol",
    "benchmark/stage1_fact_extraction/contracts/ExpirySessionAccount.sol",
    "benchmark/stage1_fact_extraction/contracts/SimpleOwnerAccount.sol",
])
def test_rename_invariance_synthesis_templates(sol_path: str):
    """
    Assert that fact-driven synthesis produces the exact same PropertyType set
    for renamed contracts as for original contracts.
    """
    orig_facts = extract_facts(sol_path)
    synthesizer = PropertySynthesizer(live=False)
    orig_props = synthesizer.synthesize(orig_facts, [], mode="full_specguard")
    orig_types = sorted(list(set(p.template_type for p in orig_props)))

    scratch_dir = os.path.abspath("scratch/renamed_contracts")
    renamed_path, renamed_name = _create_renamed_contract(sol_path, scratch_dir)
    renamed_facts = extract_facts(renamed_path, target_contract_name=renamed_name)
    renamed_props = synthesizer.synthesize(renamed_facts, [], mode="full_specguard")
    renamed_types = sorted(list(set(p.template_type for p in renamed_props)))

    assert orig_types == renamed_types, (
        f"Synthesis template selection rename-invariance FAILED for {os.path.basename(sol_path)}!\n"
        f"Original property types: {orig_types}\n"
        f"Renamed property types:  {renamed_types}"
    )
