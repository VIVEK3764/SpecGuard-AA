# SPDX-License-Identifier: MIT
"""
Validation Backend Dispatcher for SpecGuard-AA (Paper Algorithm 1 Lines 22-27).
Maps normalized properties p_hat to executable validation backends by property type tau.
Phase F Complete: Clean tri-backend verification engine
(FoundryFuzzBackend, TraceMonitorBackend, DifferentialSimBackend).
"""

from typing import List, Optional, Dict
from specguard.backends.base import ValidationBackend
from specguard.backends.foundry_fuzz import FoundryFuzzBackend
from specguard.backends.trace_monitor import TraceMonitorBackend
from specguard.backends.differential_sim import DifferentialSimBackend
from specguard.models import (
    ContractFacts,
    Property,
    PropertyBinding,
    PropertyType,
    Witness,
    ValidationResult,
    Outcome,
)


class BackendDispatcher:
    """
    Dispatches normalized properties to appropriate validation backends (Phase F).
    Guarantees full coverage over all PropertyType variants using the verified tri-backend suite.
    """

    def __init__(self):
        # Canonical tri-backend suite (Step F5)
        self.fuzz_backend = FoundryFuzzBackend()
        self.trace_backend = TraceMonitorBackend()
        self.sim_backend = DifferentialSimBackend()

        self.dispatch_map: Dict[PropertyType, List[ValidationBackend]] = {
            PropertyType.AUTH: [self.fuzz_backend],
            PropertyType.SESSION: [self.fuzz_backend],
            PropertyType.NONCE: [self.fuzz_backend],
            PropertyType.PAYMASTER: [self.fuzz_backend],
            PropertyType.SCOPE: [self.trace_backend],
            PropertyType.SIM: [self.sim_backend],
        }

    def validate_property(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> ValidationResult:
        """
        Validate property using dispatched backends by property type tau.
        Returns a structured ValidationResult with Outcome (VIOLATED, HELD, HARNESS_ERROR, TIMEOUT).
        """
        backends = self.dispatch_map.get(property.template_type)
        if not backends:
            backends = [self.fuzz_backend]
        
        last_error_res: Optional[ValidationResult] = None
        for backend in backends:
            res = backend.validate(property, binding, facts)
            if res.outcome == Outcome.VIOLATED:
                return res
            if res.outcome in (Outcome.HARNESS_ERROR, Outcome.TIMEOUT):
                last_error_res = res

        if last_error_res is not None:
            return last_error_res

        default_backend_name = backends[0].__class__.__name__ if backends else "Dispatcher"
        return ValidationResult(
            outcome=Outcome.HELD,
            backend=default_backend_name,
            property_id=property.property_id,
        )
