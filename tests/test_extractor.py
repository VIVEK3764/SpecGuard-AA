# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA Slither Fact Extractor (Step 1).
Validates E(c) extraction on Worked Example 1 (SessionAccount) and Worked Example 2 (CouponPaymaster).
"""

import os
import pytest
from specguard.models import Role
from specguard.extractor import extract_facts


SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
COUPON_PAYMASTER_PATH = os.path.join(
    "contracts", "src", "worked_examples", "CouponPaymaster.sol"
)


def test_extract_facts_session_account():
    facts = extract_facts(SESSION_ACCOUNT_PATH)

    assert facts.contract_name == "SessionAccount"
    assert Role.ACCOUNT in facts.roles

    # Check function facts
    val_fn = facts.get_function("validateUserOp")
    assert val_fn is not None
    assert val_fn.visibility in ["external", "public"]
    assert any(p["name"] in ["op", "userOp"] for p in val_fn.parameters)

    exec_fn = facts.get_function("execute")
    assert exec_fn is not None

    # Check state variable facts & role tags
    owner_var = facts.get_state_var("owner")
    assert owner_var is not None
    assert owner_var.role_tag == "owner"

    session_key_var = facts.get_state_var("sessionKey")
    assert session_key_var is not None
    assert session_key_var.role_tag == "session_key_map"

    allowed_target_var = facts.get_state_var("allowedTarget")
    assert allowed_target_var is not None
    assert allowed_target_var.role_tag == "allowed_target_map"

    # Data-flow verification: validateUserOp reads sessionKey but NOT allowedTarget
    val_df = next(df for df in facts.data_flows if df.function_name == "validateUserOp")
    assert "sessionKey" in val_df.state_vars_read
    assert "allowedTarget" not in val_df.state_vars_read, (
        "BUG DEMO: validateUserOp fails to check allowedTarget!"
    )

    # AA facts
    assert facts.aa_facts.uses_signature_recovery is True
    assert "validateUserOp" in facts.aa_facts.validation_functions


def test_extract_facts_coupon_paymaster():
    facts = extract_facts(COUPON_PAYMASTER_PATH)

    assert facts.contract_name == "CouponPaymaster"
    assert Role.PAYMASTER in facts.roles

    # Check function facts
    val_fn = facts.get_function("validatePaymasterUserOp")
    assert val_fn is not None
    assert val_fn.visibility in ["external", "public"]

    post_fn = facts.get_function("postOp")
    assert post_fn is not None

    # Check state variable facts & role tags
    sponsor_var = facts.get_state_var("sponsor")
    assert sponsor_var is not None
    assert sponsor_var.role_tag == "sponsor"

    used_coupon_var = facts.get_state_var("usedCoupon")
    assert used_coupon_var is not None
    assert used_coupon_var.role_tag == "used_coupon_map"

    # Data-flow verification: validatePaymasterUserOp reads sponsor but NOT usedCoupon
    val_df = next(
        df for df in facts.data_flows if df.function_name == "validatePaymasterUserOp"
    )
    assert "sponsor" in val_df.state_vars_read
    assert "usedCoupon" not in val_df.state_vars_read, (
        "BUG DEMO: validatePaymasterUserOp fails to check usedCoupon!"
    )

    # AA facts
    assert facts.aa_facts.decodes_paymaster_data is True
    assert facts.aa_facts.uses_signature_recovery is True
    assert "validatePaymasterUserOp" in facts.aa_facts.validation_functions
