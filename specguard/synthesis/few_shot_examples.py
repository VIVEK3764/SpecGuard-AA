# SPDX-License-Identifier: MIT
"""
Few-Shot Examples Library for SpecGuard-AA Synthesis (Step E2).
Sourced exclusively from non-benchmark, non-evaluation contracts to ensure
complete disjointness and eliminate template/variable leakage.
"""

from typing import List, Dict, Any


# Disjoint few-shot examples (sourced from hypothetical/generic non-benchmark contracts)
DISJOINT_FEWSHOT_EXAMPLES: List[Dict[str, Any]] = [
    {
        "name": "Generic Threshold Signature Translation",
        "contract_source": "GenericThresholdApprover.sol (Non-Benchmark)",
        "obligation": {
            "id": "GEN-AUTH-001",
            "statement": "An operation must be authorized by a registered approver key.",
        },
        "output": {
            "property_id": "PROP-GEN-AUTH-001",
            "template_type": "AUTH",
            "target_role": "Account",
            "bindings": {
                "validator_function": "validateUserOp",
                "key_mapping": "authorizedSigners",
            },
            "precondition": "success(validateUserOp(op))",
            "required_condition": "signedBy(op, key) AND memberOf(key, authorizedSigners)",
            "source_chunk_ids": ["CHUNK-GENERIC-AUTH-01"],
        },
    },
    {
        "name": "Generic Rate-Limited Execution Window",
        "contract_source": "RateLimitedDispatcher.sol (Non-Benchmark)",
        "obligation": {
            "id": "GEN-TIME-002",
            "statement": "An execution window must not be evaluated after its designated validity deadline.",
        },
        "output": {
            "property_id": "PROP-GEN-TIME-002",
            "template_type": "SESSION",
            "target_role": "Account",
            "bindings": {
                "validator_function": "validateUserOp",
                "custom_bindings": {"deadline_variable": "validUntil"},
            },
            "precondition": "success(validateUserOp(op))",
            "required_condition": "before(op.timestamp, validUntil)",
            "source_chunk_ids": ["CHUNK-GENERIC-TIME-02"],
        },
    },
]


def format_disjoint_few_shots() -> str:
    """Format disjoint few-shot examples for the prompt."""
    res = "Few-Shot Translation Examples (Disjoint generic reference only):\n"
    for idx, ex in enumerate(DISJOINT_FEWSHOT_EXAMPLES, 1):
        res += f"\nExample {idx} ({ex['name']} on {ex['contract_source']}):\n"
        res += f"Obligation ID: {ex['obligation']['id']}\n"
        res += f"Obligation: \"{ex['obligation']['statement']}\"\n"
        res += "Generated Formal Property:\n"
        res += "```json\n"
        import json
        res += json.dumps(ex["output"], indent=2) + "\n"
        res += "```\n"
    return res
