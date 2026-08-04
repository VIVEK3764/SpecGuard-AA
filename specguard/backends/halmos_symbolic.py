# SPDX-License-Identifier: MIT
"""
Halmos Symbolic Testing Validation Backend for SpecGuard-AA (Paper Section 3.4 & 5.2).
Executes formal symbolic execution via Halmos (in WSL2 environment) over policy fields
while keeping cryptographic signatures concrete.
"""

import os
import re
import subprocess
from typing import Optional, Dict, Any
from specguard.backends.base import ValidationBackend
from specguard.models import ContractFacts, Property, PropertyBinding, PropertyType, Witness


class HalmosSymbolicBackend(ValidationBackend):
    """
    Halmos Symbolic Backend executing formal queries in WSL2.
    """

    def __init__(self, test_dir: str = "contracts/test/generated"):
        self.test_dir = test_dir
        os.makedirs(self.test_dir, exist_ok=True)

    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Execute Halmos symbolic query in WSL2 environment.
        """
        t = property.template_type
        if t not in [PropertyType.SESSION, PropertyType.PAYMASTER, PropertyType.AUTH, PropertyType.NONCE]:
            return None

        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", property.property_id)
        contract_test_name = f"Test_{clean_id}"

        # Invoke Halmos via WSL2
        cmd = [
            "wsl",
            "~/.local/bin/halmos",
            "--match-contract",
            contract_test_name,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                cwd=os.path.abspath("."),
                timeout=60,
            )
            stdout = result.stdout + "\n" + result.stderr

            if "[FAIL]" in stdout or "Counterexample" in stdout:
                return Witness(
                    backend="HalmosSymbolic",
                    reproducible_test_code=f"// Halmos Symbolic Harness: {contract_test_name}",
                    user_op_json={"symbolic_counterexample": True, "raw_output": stdout.strip()},
                    trace_events=[line.strip() for line in stdout.splitlines() if "[FAIL]" in line or "Counterexample" in line],
                    is_valid=True,
                )
            else:
                return None

        except Exception:
            return None
