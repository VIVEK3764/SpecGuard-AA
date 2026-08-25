# SPDX-License-Identifier: MIT
"""
SpecGuard-AA Obligations Package (Phase B).
Provides compiled rules (O_Sigma), dispersed obligations (O_D), and authority scoring.
"""

from specguard.obligations.models import (
    Obligation,
    ObligationKind,
    Stream,
    Authority,
)
from specguard.obligations.erc7562 import SelectRules, COMPILED_ERC7562_RULES
from specguard.obligations.dispersed import (
    SelectDispersedObligations,
    load_dispersed_obligations,
    DISPERSED_SEED_OBLIGATIONS,
)
from specguard.obligations.authority import compute_authority, resolve_conflicts

__all__ = [
    "Obligation",
    "ObligationKind",
    "Stream",
    "Authority",
    "SelectRules",
    "COMPILED_ERC7562_RULES",
    "SelectDispersedObligations",
    "load_dispersed_obligations",
    "DISPERSED_SEED_OBLIGATIONS",
    "compute_authority",
    "resolve_conflicts",
]
