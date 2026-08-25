# SPDX-License-Identifier: MIT
"""
Core Data Models for SpecGuard-AA Obligation Inventory (Phase B).
Defines Obligation, Authority scoring model, ObligationKind, and Stream.
"""

from enum import Enum
from typing import List, Set, Dict, Any, Optional
from pydantic import BaseModel, Field


class ObligationKind(str, Enum):
    FORBIDDEN_OPCODE = "FORBIDDEN_OPCODE"
    STORAGE_SCOPE = "STORAGE_SCOPE"
    COMMITMENT = "COMMITMENT"
    POLICY = "POLICY"
    ORDERING = "ORDERING"


class Stream(str, Enum):
    COMPILED = "COMPILED"
    RETRIEVED = "RETRIEVED"


class Authority(BaseModel):
    modal_strength: str = "MUST"  # "MUST", "SHOULD", "MAY" / "descriptive"
    corroboration: int = 1         # Number of independent sources
    specificity: str = "field-level" # "field-level", "general-advice"
    score: float = 1.0

    def compute_score(self, w1: float = 0.4, w2: float = 0.3, w3: float = 0.3) -> float:
        modal_val = 1.0 if self.modal_strength.upper() in ["MUST", "SHALL"] else (0.6 if self.modal_strength.upper() == "SHOULD" else 0.3)
        corr_val = 1.0 if self.corroboration >= 2 else 0.7
        spec_val = 1.0 if self.specificity in ["field-level", "opcode-level", "concrete"] else 0.5
        self.score = round(w1 * modal_val + w2 * corr_val + w3 * spec_val, 4)
        return self.score


class Obligation(BaseModel):
    id: str                                  # e.g. "ERC7562-OP-011" or "DIG-001"
    statement: str                           # Normative requirement statement
    triggers: Set[str] = Field(default_factory=set) # Mechanism tags from A3 vocabulary
    scope: Set[str] = Field(default_factory=lambda: {"0.6", "0.7", "0.8"})
    authority: Authority = Field(default_factory=Authority)
    sources: List[str] = Field(default_factory=list) # Chunk IDs, URLs, commit hashes
    kind: ObligationKind
    payload: Dict[str, Any] = Field(default_factory=dict)
    stream: Stream = Stream.COMPILED
    conflicts_with: List[str] = Field(default_factory=list)
    date_added: Optional[str] = None
