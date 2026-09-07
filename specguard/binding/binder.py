# SPDX-License-Identifier: MIT
"""
Property Normalization, Grounding, and Binding Engine for SpecGuard-AA (Algorithm 1 Lines 10-20).
Validates Supported(), SentenceLevelGrounding(), Normalize(), TemplateCheck(), TypeCheck(), and Bind(p, E(c))
with explicit confidence-threshold scoring and zero arbitrary fallback citations.
"""

import re
from typing import List, Optional, Tuple, Dict
from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
)
from specguard.retrieval.corpus import CorpusChunk
from specguard.binding.grounding import SentenceLevelGroundingEngine, GroundingRejection


class NormalizerAndBinder:
    """
    Normalizes candidate properties, validates sentence-level grounding against cited evidence,
    and binds abstract symbols to concrete AST elements.
    """

    def __init__(self, confidence_threshold: float = 0.65):
        self.confidence_threshold = confidence_threshold
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

        # 5. Symbol Binding with Confidence Thresholding
        binding = self.bind(normalized_prop, facts)
        if binding is None:
            return None

        normalized_prop.bindings = binding
        return (normalized_prop, binding)

    def validate_grounding(self, property: Property, evidence_chunks: List[CorpusChunk]) -> Optional[Property]:
        """
        Validates per-obligation grounding with sentence-level co-occurrence.
        Returns the grounded Property if supported, or None if rejected.
        """
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
            has_session_state = any(
                sv.role_tag in ["session_key_map", "allowed_target_map", "expiry_map"]
                or "session" in sv.name.lower()
                for sv in facts.state_variables
            )
            return has_session_state

        if t == PropertyType.PAYMASTER:
            if not facts.has_role(Role.PAYMASTER):
                return False
            return facts.get_function("validatePaymasterUserOp") is not None

        if t == PropertyType.AUTH or t == PropertyType.NONCE:
            return facts.has_role(Role.ACCOUNT)

        if t == PropertyType.SCOPE or t == PropertyType.SIM:
            return len(facts.aa_facts.validation_functions) > 0

        return False

    def bind(self, property: Property, facts: ContractFacts) -> Optional[PropertyBinding]:
        binding = PropertyBinding()
        t = property.template_type
        confidence = 0.0

        if t == PropertyType.SESSION:
            val_fn = facts.get_function("validateUserOp")
            if not val_fn:
                return None
            binding.validator_function = "validateUserOp"
            confidence += 0.3

            key_candidates = [
                sv for sv in facts.state_variables
                if sv.role_tag == "session_key_map" or (sv.role_tag is None and "session" in sv.name.lower() and "expiry" not in sv.name.lower())
            ]
            if len(key_candidates) == 1:
                binding.key_mapping = key_candidates[0].name
                confidence += 0.35
            elif len(key_candidates) > 1:
                return None
            else:
                return None

            target_candidates = [
                sv for sv in facts.state_variables
                if sv.role_tag == "allowed_target_map" or (sv.role_tag is None and "target" in sv.name.lower())
            ]
            if len(target_candidates) == 1:
                binding.target_policy_mapping = target_candidates[0].name
                confidence += 0.35
            elif len(target_candidates) > 1:
                return None

            expiry_candidates = [
                sv for sv in facts.state_variables
                if sv.role_tag == "expiry_map" or (sv.role_tag is None and "expiry" in sv.name.lower())
            ]
            if len(expiry_candidates) == 1:
                binding.custom_bindings["expiry_mapping"] = expiry_candidates[0].name
                confidence += 0.35
            elif len(expiry_candidates) > 1:
                return None

            binding.target_expression = "op.callData.target"

            if confidence >= self.confidence_threshold:
                return binding
            return None

        if t == PropertyType.PAYMASTER:
            val_fn = facts.get_function("validatePaymasterUserOp")
            if not val_fn:
                return None
            binding.validator_function = "validatePaymasterUserOp"
            confidence += 0.3

            sponsor_candidates = [
                sv for sv in facts.state_variables
                if sv.role_tag == "sponsor" or (sv.role_tag is None and "sponsor" in sv.name.lower())
            ]
            if len(sponsor_candidates) == 1:
                binding.sponsor_variable = sponsor_candidates[0].name
                confidence += 0.35
            elif len(sponsor_candidates) > 1:
                return None
            else:
                return None

            coupon_candidates = [
                sv for sv in facts.state_variables
                if sv.role_tag == "used_coupon_map" or (sv.role_tag is None and "coupon" in sv.name.lower())
            ]
            if len(coupon_candidates) == 1:
                binding.used_coupon_mapping = coupon_candidates[0].name
                confidence += 0.35
            elif len(coupon_candidates) > 1:
                return None

            if confidence >= self.confidence_threshold:
                return binding
            return None

        if t in [PropertyType.AUTH, PropertyType.NONCE, PropertyType.SCOPE, PropertyType.SIM]:
            binding.validator_function = (
                "validatePaymasterUserOp"
                if facts.has_role(Role.PAYMASTER)
                else "validateUserOp"
            )
            return binding

        return None
