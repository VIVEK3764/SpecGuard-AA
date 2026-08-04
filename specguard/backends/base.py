# SPDX-License-Identifier: MIT
"""
Common Interface for SpecGuard-AA Validation Backends (Paper Algorithm 1 Line 22).
Defines Validate(p_hat, b, c) -> Witness | ⊥
"""

from abc import ABC, abstractmethod
from typing import Optional
from specguard.models import ContractFacts, Property, PropertyBinding, Witness


class ValidationBackend(ABC):
    """
    Abstract Base Class for executable formal validation backends.
    """

    @abstractmethod
    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Validate property against target contract facts E(c).
        Returns a Witness object if a concrete violation is found,
        or None (⊥) if no counterexample exists.
        """
        pass
