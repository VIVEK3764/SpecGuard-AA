# SPDX-License-Identifier: MIT
"""
Common Interface for SpecGuard-AA Validation Backends (Paper Algorithm 1 Line 22).
Defines Validate(p_hat, b, c) -> Witness | ⊥
"""

from abc import ABC, abstractmethod
from typing import Optional
from specguard.models import ContractFacts, Property, PropertyBinding, Witness, ValidationResult, Outcome


class ValidationBackend(ABC):
    """
    Abstract Base Class for executable formal validation backends.
    """

    @abstractmethod
    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> ValidationResult:
        """
        Validate property against target contract facts E(c).
        Returns a structured ValidationResult with outcome:
        - Outcome.VIOLATED (with witness)
        - Outcome.HELD (invariant confirmed)
        - Outcome.HARNESS_ERROR (compilation / setup / harness syntax error)
        - Outcome.TIMEOUT (execution timed out)
        """
        pass
