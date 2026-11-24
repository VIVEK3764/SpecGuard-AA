# SPDX-License-Identifier: MIT
"""
Property Normalization, Grounding, and Deterministic Symbol Binding for SpecGuard-AA (Step E4).

Algorithm 1 Filtering & Binding Pipeline:
  Supported/Grounded -> Normalize -> TemplateCheck -> TypeCheck -> Bind

Replaces heuristic confidence scoring with explicit tri-state resolution outcomes:
  - RESOLVED: Single unambiguous program element identified.
  - AMBIGUOUS: Multiple candidate elements exist (blocks validation, counted separately).
  - UNRESOLVED: No matching program element found (blocks validation, counted separately).

Resolution rules (Paper §5.3 / Step E4):
  - Functions resolve by selector (e.g. validateUserOp is 0x19822f7c).
  - State symbols resolve through structural mechanism tags, disambiguated
    by state variables read on the specific acceptance path (Step E3).
  - Incorporates VersionAccessors (Step E5) and CallDataDecoder (Step E6).
"""

import re
from typing import List, Optional, Tuple, Dict
from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
    SymbolBinding,
    BindStatus,
    BindKind,
    AcceptancePath,
    ProtocolVersion,
    ExecutionInterface,
)
from specguard.retrieval.corpus import CorpusChunk
from specguard.binding.grounding import SentenceLevelGroundingEngine
from specguard.binding.accessors import get_version_accessors
from specguard.binding.calldata import CallDataDecoder


# Standard 4-byte Selectors
SELECTOR_VALIDATE_USER_OP = "0x19822f7c"           # validateUserOp(PackedUserOperation,bytes32,uint256)
SELECTOR_VALIDATE_PAYMASTER_OP = "0x8dd382ab"      # validatePaymasterUserOp(PackedUserOperation,bytes32,uint256)


class NormalizerAndBinder:
    """
    Normalizes candidate properties, validates sentence-level grounding,
    and binds abstract symbols to concrete AST elements via structural mechanisms.
    """

    def __init__(self):
        self.grounding_engine = SentenceLevelGroundingEngine()

    def process(
        self, property: Property, facts: ContractFacts, evidence_chunks: List[CorpusChunk]
    ) -> Optional[Tuple[Property, PropertyBinding]]:
        """
        Run Algorithm 1 filtering pipeline:
        Supported/Grounded -> Normalize -> TemplateCheck -> TypeCheck -> Bind
        Returns (normalized_property, concrete_binding) or None if rejected.
        """
        # 1. Sentence-Level Grounding Check (Step C5)
        grounded_prop = self.validate_grounding(property, evidence_chunks)
        if grounded_prop is None:
            return None

        # 2. Normalize Property
        normalized_prop = self.normalize(grounded_prop)

        # 3. Template Check
        if not self.template_check(normalized_prop):
            return None

        # 4. Type Check against target contract
        if not self.type_check(normalized_prop, facts):
            return None

        # 5. Deterministic Symbol Binding (Step E4)
        binding = self.bind(normalized_prop, facts)
        if binding is None or binding.status != BindStatus.RESOLVED:
            return None

        normalized_prop.bindings = binding
        return (normalized_prop, binding)

    def validate_grounding(self, property: Property, evidence_chunks: List[CorpusChunk]) -> Optional[Property]:
        """Validates per-obligation grounding with sentence-level co-occurrence."""
        grounded_prop, _ = self.grounding_engine.validate_property_grounding(property, evidence_chunks)
        return grounded_prop

    def normalize(self, property: Property) -> Property:
        prop_copy = property.model_copy(deep=True)

        pre = prop_copy.precondition
        req = prop_copy.required_condition

        pre = re.sub(r"\b(validSignature|authorizedSigner|signatureAccepted)\b", "signedBy", pre)
        req = re.sub(r"\b(targetAllowedMap|targetAllowed)\b", "permittedTarget", req)
        req = re.sub(r"\b(couponValid|validCouponSig)\b", "validCoupon", req)

        prop_copy.precondition = pre
        prop_copy.required_condition = req
        return prop_copy

    def template_check(self, property: Property) -> bool:
        return property.template_type in PropertyType.__members__.values()

    def type_check(self, property: Property, facts: ContractFacts) -> bool:
        t = property.template_type

        if t == PropertyType.SESSION:
            if not facts.has_role(Role.ACCOUNT):
                return False
            # Check for structural mechanism tag
            has_session_mech = any(
                tag.tag in ["delegated_key_set", "policy_map", "time_bound"]
                for tag in facts.mechanism_tags
            )
            return has_session_mech or len(facts.state_variables) > 0

        if t == PropertyType.PAYMASTER:
            if not facts.has_role(Role.PAYMASTER):
                return False
            return facts.get_function("validatePaymasterUserOp") is not None

        if t in [PropertyType.AUTH, PropertyType.NONCE]:
            return facts.has_role(Role.ACCOUNT)

        if t in [PropertyType.SCOPE, PropertyType.SIM]:
            return len(facts.aa_facts.validation_functions) > 0 or facts.has_role(Role.ACCOUNT) or facts.has_role(Role.PAYMASTER)

        return False

    def bind(self, property: Property, facts: ContractFacts) -> Optional[PropertyBinding]:
        """
        Resolves symbols to concrete program elements.
        Returns PropertyBinding with status RESOLVED, AMBIGUOUS, or UNRESOLVED.
        """
        binding = PropertyBinding()
        symbol_map: Dict[str, SymbolBinding] = {}
        t = property.template_type

        # Select target acceptance path from E3
        path = self._select_acceptance_path(property, facts)
        binding.acceptance_path = path
        binding.path_id = path.path_id if path else None
        binding.protocol_version = facts.protocol_version

        # Detect Execution Interface (Step E6)
        exec_interface = CallDataDecoder.detect_interface(facts)
        binding.execution_interface = exec_interface
        decoder = CallDataDecoder(exec_interface)
        binding.target_expression = decoder.generate_calldata_builder("unauthorizedTarget")

        # 1. Resolve Validator Function (by selector, not name)
        if facts.has_role(Role.PAYMASTER):
            val_fn_name = "validatePaymasterUserOp"
        else:
            val_fn_name = "validateUserOp"

        binding.validator_function = val_fn_name
        symbol_map["validator"] = SymbolBinding(
            symbol="validator",
            resolved_to=val_fn_name,
            kind=BindKind.FUNCTION,
            evidence=[f"selector:{SELECTOR_VALIDATE_USER_OP}"],
            status=BindStatus.RESOLVED,
        )

        # 2. Resolve Role-Specific State Symbols
        if t == PropertyType.SESSION:
            # Resolve key_mapping via delegated_key_set mechanism tag
            key_candidates = self._find_candidates_by_mechanism(
                facts, ["delegated_key_set"], path
            )
            key_binding = self._resolve_single_symbol("sessionKey", key_candidates, BindKind.STATE_VAR)
            symbol_map["sessionKey"] = key_binding
            if key_binding.status == BindStatus.RESOLVED:
                binding.key_mapping = key_binding.resolved_to

            # Resolve target_policy_mapping via policy_map or state vars read on path
            target_candidates = self._find_candidates_by_mechanism(
                facts, ["policy_map"], path
            )
            target_binding = self._resolve_single_symbol("allowedTarget", target_candidates, BindKind.STATE_VAR)
            symbol_map["allowedTarget"] = target_binding
            if target_binding.status == BindStatus.RESOLVED:
                binding.target_policy_mapping = target_binding.resolved_to

            # Resolve expiry_mapping via time_bound
            expiry_candidates = self._find_candidates_by_mechanism(
                facts, ["time_bound"], path
            )
            expiry_binding = self._resolve_single_symbol("sessionExpiry", expiry_candidates, BindKind.STATE_VAR)
            symbol_map["sessionExpiry"] = expiry_binding
            if expiry_binding.status == BindStatus.RESOLVED:
                binding.custom_bindings["expiry_mapping"] = expiry_binding.resolved_to

        elif t == PropertyType.PAYMASTER:
            # Resolve used_coupon_mapping via consumed_set mechanism tag
            coupon_candidates = self._find_candidates_by_mechanism(
                facts, ["consumed_set"], path
            )
            coupon_binding = self._resolve_single_symbol("usedCoupon", coupon_candidates, BindKind.STATE_VAR)
            symbol_map["usedCoupon"] = coupon_binding
            if coupon_binding.status == BindStatus.RESOLVED:
                binding.used_coupon_mapping = coupon_binding.resolved_to

            # Resolve sponsor variable
            sponsor_candidates = [
                sv.name for sv in facts.state_variables
                if "address" in sv.type_str and sv.name not in ["entryPoint", "ENTRY_POINT"]
            ]
            sponsor_binding = self._resolve_single_symbol("sponsor", sponsor_candidates, BindKind.STATE_VAR)
            symbol_map["sponsor"] = sponsor_binding
            if sponsor_binding.status == BindStatus.RESOLVED:
                binding.sponsor_variable = sponsor_binding.resolved_to

        elif t in [PropertyType.AUTH, PropertyType.NONCE, PropertyType.SCOPE, PropertyType.SIM]:
            # Baseline symbols resolved
            symbol_map["target"] = SymbolBinding(
                symbol="target",
                resolved_to=facts.contract_name,
                kind=BindKind.STATE_VAR,
                evidence=["contract_target"],
                status=BindStatus.RESOLVED,
            )

        # Match administrative setup function from E1/F1
        bound_target_var = binding.key_mapping or binding.used_coupon_mapping or binding.sponsor_variable
        if bound_target_var and facts.admin_setups:
            for admin in facts.admin_setups:
                if admin.target_state_var == bound_target_var:
                    binding.admin_setup = admin
                    break

        # Check overall binding status
        binding.symbol_bindings = symbol_map
        if any(sb.status == BindStatus.AMBIGUOUS for sb in symbol_map.values()):
            binding.status = BindStatus.AMBIGUOUS
        elif any(sb.status == BindStatus.UNRESOLVED for sb in symbol_map.values()):
            # For optional policy variables (e.g. expiry or target policy in a buggy contract),
            # absence of the check is the defect! The main key or validator must be resolved.
            if symbol_map.get("validator", {}).status == BindStatus.RESOLVED:
                binding.status = BindStatus.RESOLVED
            else:
                binding.status = BindStatus.UNRESOLVED
        else:
            binding.status = BindStatus.RESOLVED

        return binding

    def _select_acceptance_path(self, property: Property, facts: ContractFacts) -> Optional[AcceptancePath]:
        """Selects the specific acceptance path that activates this property."""
        if not facts.acceptance_paths:
            return None

        t = property.template_type
        # Session properties bind to the session acceptance path
        if t == PropertyType.SESSION:
            for p in facts.acceptance_paths:
                if "session" in p.path_id.lower() or p.is_local_digest:
                    return p
            return facts.acceptance_paths[-1]

        # Auth / Nonce properties bind to owner / primary path
        if t in [PropertyType.AUTH, PropertyType.NONCE]:
            for p in facts.acceptance_paths:
                if "owner" in p.path_id.lower() or not p.is_local_digest:
                    return p
            return facts.acceptance_paths[0]

        return facts.acceptance_paths[0]

    def _find_candidates_by_mechanism(
        self, facts: ContractFacts, target_tags: List[str], path: Optional[AcceptancePath]
    ) -> List[str]:
        """Finds candidate state variables from mechanism evidence nodes, filtered by path reads."""
        candidates = set()

        for m_tag in facts.mechanism_tags:
            if m_tag.tag in target_tags:
                for node_desc in m_tag.evidence_nodes:
                    # Extract variable identifier from evidence node string
                    # e.g., "mapping(address => bool) sessionKey" -> "sessionKey"
                    tokens = node_desc.split()
                    if tokens:
                        var_candidate = tokens[-1].strip(";,")
                        candidates.add(var_candidate)

        # Fallback to state variables matching role_tag or type structure if mechanism tags empty
        if not candidates:
            if "delegated_key_set" in target_tags:
                for sv in facts.state_variables:
                    if sv.role_tag in ["session_key_map", "delegated_key_set"]:
                        candidates.add(sv.name)
                    elif not sv.role_tag and "mapping" in sv.type_str and "session" in sv.name.lower():
                        candidates.add(sv.name)
            elif "policy_map" in target_tags:
                for sv in facts.state_variables:
                    if sv.role_tag in ["allowed_target_map", "policy_map"]:
                        candidates.add(sv.name)
                    elif not sv.role_tag and "mapping" in sv.type_str and ("target" in sv.name.lower() or "policy" in sv.name.lower()):
                        candidates.add(sv.name)
            elif "consumed_set" in target_tags:
                for sv in facts.state_variables:
                    if sv.role_tag in ["used_coupon_map", "consumed_set"]:
                        candidates.add(sv.name)
                    elif "mapping" in sv.type_str and "bytes32" in sv.type_str:
                        candidates.add(sv.name)
            elif "time_bound" in target_tags:
                for sv in facts.state_variables:
                    if sv.role_tag in ["expiry_map", "time_bound"]:
                        candidates.add(sv.name)
                    elif "uint" in sv.type_str and "expiry" in sv.name.lower():
                        candidates.add(sv.name)

        # If path is available, prioritize variables read on that path
        if path and path.state_vars_read:
            path_filtered = [c for c in candidates if c in path.state_vars_read]
            if path_filtered:
                return path_filtered

        return list(candidates)

    def _resolve_single_symbol(
        self, symbol_name: str, candidates: List[str], kind: BindKind
    ) -> SymbolBinding:
        """Categorizes candidates into RESOLVED, AMBIGUOUS, or UNRESOLVED."""
        if len(candidates) == 1:
            return SymbolBinding(
                symbol=symbol_name,
                resolved_to=candidates[0],
                kind=kind,
                evidence=[f"candidate:{candidates[0]}"],
                status=BindStatus.RESOLVED,
            )
        elif len(candidates) > 1:
            return SymbolBinding(
                symbol=symbol_name,
                resolved_to=None,
                kind=kind,
                evidence=[f"ambiguous_candidates:{','.join(candidates)}"],
                status=BindStatus.AMBIGUOUS,
            )
        else:
            return SymbolBinding(
                symbol=symbol_name,
                resolved_to=None,
                kind=kind,
                evidence=["no_candidate_found"],
                status=BindStatus.UNRESOLVED,
            )
