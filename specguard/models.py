# SPDX-License-Identifier: MIT
"""
Core Data Models and Type Definitions for SpecGuard-AA.
Defines extracted facts E(c), candidate properties p, property bindings, witnesses, and security reports.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class Role(str, Enum):
    ACCOUNT = "Account"
    PAYMASTER = "Paymaster"
    FACTORY = "Factory"
    AGGREGATOR = "Aggregator"
    GENERIC = "Generic"


class PropertyType(str, Enum):
    AUTH = "AUTH"
    NONCE = "NONCE"
    SESSION = "SESSION"
    PAYMASTER = "PAYMASTER"
    SCOPE = "SCOPE"
    SIM = "SIM"


class FunctionFact(BaseModel):
    name: str
    visibility: str
    parameters: List[Dict[str, str]] = Field(default_factory=list)
    return_types: List[str] = Field(default_factory=list)
    is_external_or_public: bool = False
    modifiers: List[str] = Field(default_factory=list)
    called_functions: List[str] = Field(default_factory=list)
    state_variables_read: List[str] = Field(default_factory=list)
    state_variables_written: List[str] = Field(default_factory=list)


class StateVariableFact(BaseModel):
    name: str
    type_str: str
    visibility: str = "public"
    role_tag: Optional[str] = None


# Alias for backward compatibility
StateFact = StateVariableFact


class DataFlowFact(BaseModel):
    function_name: str
    state_vars_read: List[str] = Field(default_factory=list)
    state_vars_written: List[str] = Field(default_factory=list)
    user_op_fields_read: List[str] = Field(default_factory=list)
    influences_validation_return: bool = False


class AAFacts(BaseModel):
    entry_point_checked: bool = False
    uses_signature_recovery: bool = False
    decodes_paymaster_data: bool = False
    signature_recovery_functions: List[str] = Field(default_factory=list)
    validation_functions: List[str] = Field(default_factory=list)


# Alias for backward compatibility
AAFact = AAFacts


class ContractFacts(BaseModel):
    contract_name: str
    source_path: str
    roles: List[Role] = Field(default_factory=list)
    functions: List[FunctionFact] = Field(default_factory=list)
    state_variables: List[StateVariableFact] = Field(default_factory=list)
    data_flows: List[DataFlowFact] = Field(default_factory=list)
    aa_facts: AAFacts = Field(default_factory=AAFacts)

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def get_function(self, name: str) -> Optional[FunctionFact]:
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None

    def get_state_var(self, name: str) -> Optional[StateVariableFact]:
        for sv in self.state_variables:
            if sv.name == name:
                return sv
        return None


class PropertyBinding(BaseModel):
    validator_function: Optional[str] = None
    key_mapping: Optional[str] = None
    target_policy_mapping: Optional[str] = None
    used_coupon_mapping: Optional[str] = None
    sponsor_variable: Optional[str] = None
    target_expression: Optional[str] = None
    custom_bindings: Dict[str, str] = Field(default_factory=dict)


class Property(BaseModel):
    property_id: str
    template_type: PropertyType
    target_role: Role
    bindings: PropertyBinding = Field(default_factory=PropertyBinding)
    precondition: str
    required_condition: str
    source_chunk_ids: List[str] = Field(default_factory=list)
    raw_prompt_response: Optional[str] = None


class Witness(BaseModel):
    backend: str
    reproducible_test_code: str
    user_op_json: Dict[str, Any] = Field(default_factory=dict)
    trace_events: List[str] = Field(default_factory=list)
    is_valid: bool = True


class SecurityReport(BaseModel):
    report_id: str
    contract_name: str
    property: Property
    bindings: PropertyBinding
    retrieved_sources: List[str]
    witness: Witness
    reproduction_script_path: Optional[str] = None
    timestamp: str
