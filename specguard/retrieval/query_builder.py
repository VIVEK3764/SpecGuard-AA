# SPDX-License-Identifier: MIT
"""
Role and Phase Specific Query Builder for SpecGuard-AA.
Generates focused retrieval queries Q from contract facts E(c).
"""

from typing import List
from pydantic import BaseModel
from specguard.models import ContractFacts, Role


class RetrievalQuery(BaseModel):
    query_text: str
    target_role: str
    target_phase: str
    topic: str


def build_queries(facts: ContractFacts) -> List[RetrievalQuery]:
    """
    Construct role/phase-specific queries based on extracted contract facts E(c).
    """
    queries: List[RetrievalQuery] = []

    # 1. Smart Account Queries
    if facts.has_role(Role.ACCOUNT):
        queries.append(
            RetrievalQuery(
                query_text=f"{facts.contract_name} validateUserOp signature authorization owner validation success failure",
                target_role="account",
                target_phase="validation",
                topic="authorization",
            )
        )

        # Check for Session Key indicators in state vars
        has_session_key = any(sv.role_tag == "session_key_map" for sv in facts.state_variables)
        has_target = any(sv.role_tag == "allowed_target_map" for sv in facts.state_variables)

        if has_session_key or has_target:
            queries.append(
                RetrievalQuery(
                    query_text=f"session key policy allowedTarget callData target restriction authorization bypass",
                    target_role="account",
                    target_phase="validation",
                    topic="session key",
                )
            )

        queries.append(
            RetrievalQuery(
                query_text="account nonce freshness replay protection validateUserOp",
                target_role="account",
                target_phase="validation",
                topic="nonce",
            )
        )

    # 2. Paymaster Queries
    if facts.has_role(Role.PAYMASTER):
        queries.append(
            RetrievalQuery(
                query_text=f"{facts.contract_name} validatePaymasterUserOp sponsor coupon signature sponsorship policy",
                target_role="paymaster",
                target_phase="validation",
                topic="sponsorship",
            )
        )

        has_coupon = any(sv.role_tag == "used_coupon_map" for sv in facts.state_variables)
        has_sponsor = any(sv.role_tag == "sponsor" for sv in facts.state_variables)

        if has_coupon or has_sponsor:
            queries.append(
                RetrievalQuery(
                    query_text="coupon replay protection usedCoupon expiration timestamp sponsor signature",
                    target_role="paymaster",
                    target_phase="validation",
                    topic="sponsorship",
                )
            )

    # 3. Validation-Scope & Simulation-Consistency Queries (Applicable to all AA contracts)
    queries.append(
        RetrievalQuery(
            query_text="validation scope forbidden opcodes timestamp blockhash balance storage access restrictions",
            target_role="generic",
            target_phase="validation",
            topic="validation scope",
        )
    )

    return queries
