# SPDX-License-Identifier: MIT
"""
Core Data Models and Type Definitions for SpecGuard-AA.
Defines extracted facts E(c), candidate properties p, property bindings, witnesses, and security reports.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ProtocolVersion(str, Enum):
    V0_6 = "0.6"
    V0_7 = "0.7"
    V0_8 = "0.8"
    UNKNOWN = "unknown"


class BindStatus(str, Enum):
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class BindKind(str, Enum):
    STATE_VAR = "STATE_VAR"
    FUNCTION = "FUNCTION"
    PARAM_FIELD = "PARAM_FIELD"
    EXPRESSION = "EXPRESSION"


class ExecutionInterface(str, Enum):
    CLASSIC = "CLASSIC"          # execute(address,uint256,bytes)
    BATCH = "BATCH"              # executeBatch(...)
    ERC7579 = "ERC7579"          # execute(bytes32 mode, bytes executionCalldata)
    UNRESOLVED = "UNRESOLVED"    # ERC-6900 plugins or unknown dispatch


class SymbolBinding(BaseModel):
    """Explicit symbol resolution outcome for a single abstract symbol (Step E4)."""
    symbol: str
    resolved_to: Optional[str] = None
    kind: BindKind
    evidence: List[str] = Field(default_factory=list)
    status: BindStatus = BindStatus.UNRESOLVED


class AcceptancePath(BaseModel):
    """A distinct validation success path through the CFG (Step E3)."""
    path_id: str
    function_name: str
    return_expression: str = "VALIDATION_SUCCESS"
    digest_expression: Optional[str] = None
    is_local_digest: bool = False
    state_vars_read: List[str] = Field(default_factory=list)
    recovery_call_nodes: List[str] = Field(default_factory=list)
    path_condition: List[str] = Field(default_factory=list)


class AdminFunctionSetup(BaseModel):
    """An administrative setter function discovered to initialize state (Step F1)."""
    function_name: str
    target_state_var: str
    parameters: List[Dict[str, str]] = Field(default_factory=list)
    caller_guard: Optional[str] = None


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


class Outcome(str, Enum):
    """Structured four-valued outcome from formal validation backends (Step F2)."""
    VIOLATED = "VIOLATED"
    HELD = "HELD"
    HARNESS_ERROR = "HARNESS_ERROR"
    TIMEOUT = "TIMEOUT"


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
    unread_in_validation: List[str] = Field(default_factory=list)
    influences_validation_return: bool = False


class AAFacts(BaseModel):
    entry_point_checked: bool = False
    uses_signature_recovery: bool = False
    decodes_paymaster_data: bool = False
    signature_recovery_functions: List[str] = Field(default_factory=list)
    validation_functions: List[str] = Field(default_factory=list)


# Alias for backward compatibility
AAFact = AAFacts


class MechanismTag(BaseModel):
    tag: str
    evidence_nodes: List[str] = Field(default_factory=list)
    confidence: float = 1.0


class ContractFacts(BaseModel):
    contract_name: str
    source_path: str
    roles: List[Role] = Field(default_factory=list)
    functions: List[FunctionFact] = Field(default_factory=list)
    state_variables: List[StateVariableFact] = Field(default_factory=list)
    data_flows: List[DataFlowFact] = Field(default_factory=list)
    aa_facts: AAFacts = Field(default_factory=AAFacts)
    mechanism_tags: List[MechanismTag] = Field(default_factory=list)
    acceptance_paths: List[AcceptancePath] = Field(default_factory=list)
    protocol_version: ProtocolVersion = ProtocolVersion.V0_7
    admin_setups: List[AdminFunctionSetup] = Field(default_factory=list)

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

    def get_acceptance_path(self, path_id: str) -> Optional[AcceptancePath]:
        for path in self.acceptance_paths:
            if path.path_id == path_id:
                return path
        return None


class PropertyBinding(BaseModel):
    validator_function: Optional[str] = None
    key_mapping: Optional[str] = None
    target_policy_mapping: Optional[str] = None
    used_coupon_mapping: Optional[str] = None
    sponsor_variable: Optional[str] = None
    target_expression: Optional[str] = None
    custom_bindings: Dict[str, str] = Field(default_factory=dict)
    
    # Explicit binding fields (Steps E3, E4, E5, E6)
    path_id: Optional[str] = None
    symbol_bindings: Dict[str, SymbolBinding] = Field(default_factory=dict)
    protocol_version: ProtocolVersion = ProtocolVersion.V0_7
    execution_interface: ExecutionInterface = ExecutionInterface.CLASSIC
    admin_setup: Optional[AdminFunctionSetup] = None
    acceptance_path: Optional[AcceptancePath] = None
    status: BindStatus = BindStatus.RESOLVED


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


class ValidationResult(BaseModel):
    """Structured result returned by every validation backend (Step F2)."""
    outcome: Outcome
    backend: str
    property_id: str
    failing_obligation_id: Optional[str] = None
    witness: Optional[Witness] = None
    error_message: Optional[str] = None
    raw_artifact_path: Optional[str] = None


class SecurityReport(BaseModel):
    report_id: str
    contract_name: str
    property: Property
    bindings: PropertyBinding
    retrieved_sources: List[str]
    witness: Witness
    reproduction_script_path: Optional[str] = None
    timestamp: str
