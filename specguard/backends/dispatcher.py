# SPDX-License-Identifier: MIT
"""
Validation Backend Dispatcher for SpecGuard-AA (Paper Algorithm 1 Lines 22-27).
Maps normalized properties p_hat to executable validation backends by property type tau.
"""

from typing import List, Optional, Dict
from specguard.backends.base import ValidationBackend
from specguard.backends.foundry_fuzz import FoundryFuzzBackend
from specguard.backends.halmos_symbolic import HalmosSymbolicBackend
from specguard.backends.trace_monitor import TraceMonitorBackend
from specguard.backends.differential_sim import DifferentialSimBackend
from specguard.models import ContractFacts, Property, PropertyBinding, PropertyType, Witness


class BackendDispatcher:
    """
    Dispatches normalized properties to appropriate validation backends.
    """

    def __init__(self):
        self.fuzz_backend = FoundryFuzzBackend()
        self.halmos_backend = HalmosSymbolicBackend()
        self.trace_backend = TraceMonitorBackend()
        self.sim_backend = DifferentialSimBackend()

        self.dispatch_map: Dict[PropertyType, List[ValidationBackend]] = {
            PropertyType.AUTH: [self.fuzz_backend, self.halmos_backend],
            PropertyType.SESSION: [self.fuzz_backend, self.halmos_backend],
            PropertyType.NONCE: [self.fuzz_backend, self.halmos_backend],
            PropertyType.PAYMASTER: [self.fuzz_backend, self.halmos_backend],
            PropertyType.SCOPE: [self.trace_backend],
            PropertyType.SIM: [self.sim_backend],
        }

    def validate_property(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Validate property using dispatched backends by property type tau.
        Returns Witness object if a backend finds a concrete violation, or None (⊥).
        """
        backends = self.dispatch_map.get(property.template_type, [self.fuzz_backend])
        
        for backend in backends:
            witness = backend.validate(property, binding, facts)
            if witness is not None:
                return witness

        return None
