# SPDX-License-Identifier: MIT
"""
Template-First Property Synthesizer for SpecGuard-AA (Paper Algorithm 1 & Section 4.3).
Generates raw properties P_raw from contract facts E(c) and retrieved evidence chunks C.
Supports real LLM structured synthesis (Anthropic & OpenAI) and dynamic fact-driven template fallback.
Includes §4.3 Property Response Disk Cache and strict anti-leakage few-shot filtering.
"""

import os
import sys
import json
import hashlib
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
)
from specguard.retrieval.corpus import CorpusChunk

# Load environment variables from .env if present
load_dotenv()

# Disk cache directory for LLM raw responses (§4.3 Property Response Cache)
CACHE_DIR = os.path.join(".cache", "llm_synthesis")


def _stable_prop_id(prefix: str, type_tag: str, role: str, precond: str, req_cond: str) -> str:
    """
    Compute a deterministic, cross-run-stable property ID using SHA-256 over structural content.

    Python's built-in hash() is randomised per-process (PYTHONHASHSEED), so
    ``hash(x) % 10000`` produces different IDs across runs for the same logical
    property — breaking duplicate elimination.  This function is stable: the same
    (type, role, precondition, required_condition) always maps to the same 8-hex suffix.
    """
    content = f"{type_tag}|{role}|{precond.strip()}|{req_cond.strip()}"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"

# Allowed Predicates Whitelist per Property Type (Paper §4.3)
PREDICATE_WHITELIST = {
    PropertyType.SESSION: [
        "success", "validateUserOp", "signedBySessionKey", "target",
        "allowedTarget", "notExpired", "expiry", "nonceFresh"
    ],
    PropertyType.PAYMASTER: [
        "success", "validatePaymasterUserOp", "validCoupon", "used",
        "coupon", "sponsor", "validSignature", "notExpired"
    ],
    PropertyType.AUTH: [
        "success", "validateUserOp", "signedByOwner", "owner", "validSignature"
    ],
    PropertyType.NONCE: [
        "success", "validateUserOp", "nonceFresh"
    ],
    PropertyType.SCOPE: [
        "simulatingValidation", "forbiddenOpcodeExecuted", "externalStorageAccessed"
    ],
}

# Few-Shot Examples Library for Anti-Leakage Filtering
FEWSHOT_EXAMPLES_LIBRARY = [
    {
        "name": "Session Key Target Policy Bypass",
        "contract_name": "SessionAccount",
        "template_type": PropertyType.SESSION,
        "target_role": Role.ACCOUNT,
        "example": {
            "property_id": "PROP-SESSION-TARGET-FEWSHOT",
            "template_type": "SESSION",
            "target_role": "Account",
            "bindings": {
                "validator_function": "validateUserOp",
                "key_mapping": "sessionKey",
                "target_policy_mapping": "allowedTarget",
                "target_expression": "op.callData.target"
            },
            "precondition": "success(validateUserOp(op)) AND signedBySessionKey(op, K)",
            "required_condition": "target(op) == allowedTarget[K]",
            "source_chunk_ids": ["ERC7562-AUTH-010"]
        }
    },
    {
        "name": "Coupon Paymaster Double-Spend Replay",
        "contract_name": "CouponPaymaster",
        "template_type": PropertyType.PAYMASTER,
        "target_role": Role.PAYMASTER,
        "example": {
            "property_id": "PROP-PAYMASTER-REPLAY-FEWSHOT",
            "template_type": "PAYMASTER",
            "target_role": "Paymaster",
            "bindings": {
                "validator_function": "validatePaymasterUserOp",
                "used_coupon_mapping": "usedCoupon",
                "sponsor_variable": "sponsor"
            },
            "precondition": "success(validatePaymasterUserOp(op))",
            "required_condition": "validCoupon(op) AND NOT used(op.coupon)",
            "source_chunk_ids": ["ERC4337-SPEC-021", "AUDIT-33AUDITS-AA-001"]
        }
    },
    {
        "name": "Owner Authorization",
        "contract_name": "SimpleOwnerAccount",
        "template_type": PropertyType.AUTH,
        "target_role": Role.ACCOUNT,
        "example": {
            "property_id": "PROP-AUTH-OWNER-FEWSHOT",
            "template_type": "AUTH",
            "target_role": "Account",
            "bindings": {
                "validator_function": "validateUserOp",
                "owner_variable": "owner"
            },
            "precondition": "success(validateUserOp(op))",
            "required_condition": "signedByOwner(op, owner)",
            "source_chunk_ids": ["AUDIT-ETH-INFINITISM-README-008"]
        }
    }
]


def _build_few_shot_prompt(facts: ContractFacts) -> str:
    """
    Builds few-shot example section for the LLM prompt with strict anti-leakage filtering:
    Excludes any few-shot example that originates from the same contract or shares the 
    contract name or template type of the target contract.
    """
    valid_examples = []
    target_contract_name = facts.contract_name.lower()

    for ex in FEWSHOT_EXAMPLES_LIBRARY:
        ex_contract = ex["contract_name"].lower()

        # Rule 1: Exclude exact contract match
        if ex_contract == target_contract_name:
            continue

        # Rule 2: Cross-role / Cross-template anti-leakage filter
        if "paymaster" in target_contract_name and ex["template_type"] == PropertyType.PAYMASTER:
            continue
        if "session" in target_contract_name and ex["template_type"] == PropertyType.SESSION:
            continue

        valid_examples.append(ex)

    few_shot_str = ""
    for idx, ex in enumerate(valid_examples, start=1):
        few_shot_str += f"\nFew-Shot Example {idx} ({ex['name']}):\n"
        few_shot_str += json.dumps(ex["example"], indent=2) + "\n"

    return few_shot_str


PROMPT_TEMPLATE = """System: You are SpecGuard-AA, a formal specification mining AI for ERC-4337 Account Abstraction smart contracts.
Your task is to synthesize formal candidate security properties tuple p = (tau, target_role, bindings, precondition, required_condition, source_chunk_ids) from extracted contract facts E(c) and retrieved specification evidence C.

CRITICAL CONSTRAINTS:
1. You MUST select 'tau' ONLY from: 'SESSION', 'PAYMASTER', 'AUTH', 'NONCE', 'SCOPE'.
2. You MUST cite exact 'source_chunk_ids' present in the retrieved evidence C below (e.g. 'ERC7562-AUTH-010', 'ERC4337-SPEC-021', 'AUDIT-33AUDITS-AA-001').
3. Do NOT invent unsupported predicates. Use only whitelisted predicate functions like: success(validateUserOp(op)), signedBySessionKey(op, K), target(op) == allowedTarget[K], notExpired(K), validCoupon(op), NOT used(op.coupon), NOT forbiddenOpcodeExecuted(tr).

Extracted Contract Facts E(c):
{facts_json}

Retrieved Protocol Evidence Chunks C:
{evidence_json}
{few_shot_section}
Output structured properties matching the requested schema."""


class PropertySynthesizer:
    """
    Synthesizes candidate properties P_raw using template-first prompting & structured LLM output.
    """

    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None, model: Optional[str] = None, live: bool = False):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "anthropic")).lower()
        self.model = model or os.getenv("LLM_MODEL") or ("claude-3-5-sonnet-20241022" if self.provider == "anthropic" else "gpt-4o")
        self.live = live
        
        # Select API key safely based on provider
        if api_key:
            self.api_key = api_key
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
        else:
            self.api_key = None

        # Log credential status safely without ever exposing raw key string
        if self.api_key and self.api_key.strip():
            print(f"[+] SpecGuard Synthesizer configured for provider '{self.provider}' (Key present: True, len={len(self.api_key.strip())}, model='{self.model}')")
        else:
            print(f"[-] SpecGuard Synthesizer configured for provider '{self.provider}' (Key present: False)")

        if self.live and (not self.api_key or not self.api_key.strip()):
            raise RuntimeError(
                f"LLM_PROVIDER='{self.provider}' is configured for live synthesis, but matching API key is missing from environment/.env!"
            )

    def get_llm_prompt(self, facts: ContractFacts, evidence_chunks: List[CorpusChunk], mode: str = "full_specguard") -> str:
        """Expose the literal prompt text sent to the LLM API with mode-specific ablation configuration."""
        if mode == "zero_shot":
            facts_dict = {"contract_name": facts.contract_name, "functions": [f.name for f in facts.functions]}
            evidence_dict = []
        elif mode == "facts_only":
            facts_dict = facts.model_dump()
            evidence_dict = []
        elif mode == "rag_only":
            facts_dict = {"contract_name": facts.contract_name}
            evidence_dict = [c.model_dump() for c in evidence_chunks]
        else:
            facts_dict = facts.model_dump()
            evidence_dict = [c.model_dump() for c in evidence_chunks]

        few_shot_section = _build_few_shot_prompt(facts) if mode == "full_specguard" else ""
        return PROMPT_TEMPLATE.format(
            facts_json=json.dumps(facts_dict, indent=2),
            evidence_json=json.dumps(evidence_dict, indent=2),
            few_shot_section=few_shot_section,
        )

    def synthesize(
        self, facts: ContractFacts, evidence_chunks: List[CorpusChunk], force_live: bool = False, mode: str = "full_specguard"
    ) -> List[Property]:
        """
        Synthesize raw candidate properties P_raw from E(c) and retrieved C under mode configuration.
        """
        raw_properties: List[Property] = []

        is_live = self.live or force_live

        if is_live or (self.api_key and self.api_key.strip()):
            llm_props = self._synthesize_llm(facts, evidence_chunks, mode=mode)
            raw_properties.extend(llm_props)

        # Dynamic fact-driven property generation fallback / complement (only for full_specguard or facts_only)
        if mode in ["full_specguard", "facts_only"]:
            rule_props = self._synthesize_fact_driven(facts, evidence_chunks)
        else:
            rule_props = []

        seen_ids = set()
        combined: List[Property] = []

        for p in raw_properties + rule_props:
            if p.property_id not in seen_ids:
                seen_ids.add(p.property_id)
                combined.append(p)

        return combined

    def _get_cache_key(self, facts: ContractFacts, evidence_chunks: List[CorpusChunk], mode: str = "full_specguard") -> str:
        chunk_ids = sorted([c.id for c in evidence_chunks])
        raw_key = f"{facts.contract_name}:{facts.source_path}:{','.join(chunk_ids)}:{self.model}:{mode}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def _synthesize_llm(
        self, facts: ContractFacts, evidence_chunks: List[CorpusChunk], mode: str = "full_specguard"
    ) -> List[Property]:
        """
        Executes real structured LLM API call (Anthropic or OpenAI) with disk caching (§4.3).
        Captures full raw SDK response envelope including token usage and finish reason.
        """
        if not self.api_key or not self.api_key.strip():
            if self.live:
                raise RuntimeError(f"Missing API key for provider '{self.provider}'. Set it in .env file.")
            return []

        # Check response disk cache first
        cache_key = self._get_cache_key(facts, evidence_chunks, mode=mode)
        os.makedirs(CACHE_DIR, exist_ok=True)
        cache_path = os.path.join(CACHE_DIR, f"{cache_key}.json")

        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                print(f"[+] Loaded synthesis response from Property Cache (§4.3): {cache_path}")
                return [Property(**item) for item in cached_data]
            except Exception as e:
                print(f"[-] Cache read error: {e}")

        prompt = self.get_llm_prompt(facts, evidence_chunks, mode=mode)
        parsed_props: List[Property] = []
        raw_envelope_str = ""

        if self.provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key.strip())

            tool_schema = {
                "name": "synthesize_properties",
                "description": "Output formal candidate security properties for ERC-4337 contract",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "properties": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "property_id": {"type": "string"},
                                    "template_type": {
                                        "type": "string",
                                        "enum": ["SESSION", "PAYMASTER", "AUTH", "NONCE", "SCOPE"],
                                    },
                                    "target_role": {"type": "string"},
                                    "bindings": {
                                        "type": "object",
                                        "properties": {
                                            "validator_function": {"type": "string"},
                                            "key_mapping": {"type": "string"},
                                            "target_policy_mapping": {"type": "string"},
                                            "used_coupon_mapping": {"type": "string"},
                                            "sponsor_variable": {"type": "string"},
                                            "target_expression": {"type": "string"},
                                        },
                                    },
                                    "precondition": {"type": "string"},
                                    "required_condition": {"type": "string"},
                                    "source_chunk_ids": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                                "required": [
                                    "property_id",
                                    "template_type",
                                    "target_role",
                                    "precondition",
                                    "required_condition",
                                    "source_chunk_ids",
                                ],
                            },
                        }
                    },
                    "required": ["properties"],
                },
            }

            resp = client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "synthesize_properties"},
            )

            raw_envelope_str = resp.model_dump_json(indent=2)
            for block in resp.content:
                if block.type == "tool_use" and block.name == "synthesize_properties":
                    props_list = block.input.get("properties", [])
                    for item in props_list:
                        p = self._parse_and_validate_property(item, raw_envelope_str)
                        if p:
                            parsed_props.append(p)

        elif self.provider == "openai":
            import openai
            client = openai.OpenAI(api_key=self.api_key.strip())

            response_format = {
                "type": "json_schema",
                "json_schema": {
                    "name": "synthesize_properties_response",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "properties": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "property_id": {"type": "string"},
                                        "template_type": {"type": "string"},
                                        "target_role": {"type": "string"},
                                        "bindings": {"type": "object"},
                                        "precondition": {"type": "string"},
                                        "required_condition": {"type": "string"},
                                        "source_chunk_ids": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                    },
                                    "required": [
                                        "property_id",
                                        "template_type",
                                        "target_role",
                                        "precondition",
                                        "required_condition",
                                        "source_chunk_ids",
                                    ],
                                }
                            }
                        },
                        "required": ["properties"],
                    },
                },
            }

            resp = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format=response_format,
            )

            raw_envelope_str = resp.model_dump_json(indent=2)
            raw_response_text = resp.choices[0].message.content or ""
            cleaned_text = raw_response_text.strip()
            if cleaned_text.startswith("```"):
                cleaned_text = re.sub(r"^```(?:json)?\s*", "", cleaned_text)
                cleaned_text = re.sub(r"\s*```$", "", cleaned_text)

            try:
                parsed_json = json.loads(cleaned_text)
                if isinstance(parsed_json, dict) and "properties" in parsed_json:
                    for item in parsed_json.get("properties", []):
                        if isinstance(item, dict):
                            p = self._parse_and_validate_property(item, raw_envelope_str)
                            if p:
                                parsed_props.append(p)
            except Exception as e:
                print(f"[-] JSON decode error: {e}")

        # Store in Property Response Cache (§4.3)
        if parsed_props:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump([p.model_dump() for p in parsed_props], f, indent=2)
            print(f"[+] Saved structured synthesis output to Property Cache: {cache_path}")

        return parsed_props

    def _parse_and_validate_property(
        self, item: Dict[str, Any], raw_envelope_str: str = ""
    ) -> Optional[Property]:
        """
        Parses item dict into Property object and validates predicate whitelist (Part C.4).
        Preserves raw SDK envelope string in raw_prompt_response.
        """
        try:
            t_str = item.get("template_type", "").upper()
            if t_str not in PropertyType.__members__:
                print(f"[-] Rejection: Unwhitelisted template type '{t_str}'")
                return None

            t_type = PropertyType[t_str]
            role_str = item.get("target_role", "Account")
            try:
                role = Role(role_str)
            except ValueError:
                try:
                    role = Role[role_str.upper()]
                except KeyError:
                    role = Role.ACCOUNT

            bindings_raw = item.get("bindings", {})
            bindings = PropertyBinding(
                validator_function=bindings_raw.get("validator_function", "validateUserOp"),
                key_mapping=bindings_raw.get("key_mapping"),
                target_policy_mapping=bindings_raw.get("target_policy_mapping"),
                used_coupon_mapping=bindings_raw.get("used_coupon_mapping"),
                sponsor_variable=bindings_raw.get("sponsor_variable"),
                target_expression=bindings_raw.get("target_expression"),
            )

            req_cond = item.get("required_condition", "")
            pre_cond = item.get("precondition", "")

            # Whitelist predicate validation (Part C.4)
            allowed_preds = PREDICATE_WHITELIST.get(t_type, [])
            cond_words = req_cond.replace("(", " ").replace(")", " ").replace("==", " ").split()
            for w in cond_words:
                w_clean = w.strip("!,.")
                if w_clean and w_clean.isidentifier() and not w_clean.isupper() and w_clean not in ["op", "tr", "K", "AND", "OR", "NOT"]:
                    if allowed_preds and not any(p in w_clean for p in allowed_preds):
                        print(f"[-] Rejection: Unwhitelisted predicate '{w_clean}' in required_condition for {t_type}")
                        return None

            return Property(
                property_id=item.get(
                    "property_id",
                    _stable_prop_id("PROP-LLM", t_type.value, role.value, pre_cond, req_cond),
                ),
                template_type=t_type,
                target_role=role,
                bindings=bindings,
                precondition=pre_cond,
                required_condition=req_cond,
                source_chunk_ids=item.get("source_chunk_ids", []),
                raw_prompt_response=raw_envelope_str or json.dumps(item),
            )
        except Exception as e:
            print(f"[-] Validation error parsing LLM property item: {e}")
            return None

    def _synthesize_fact_driven(
        self, facts: ContractFacts, evidence_chunks: List[CorpusChunk]
    ) -> List[Property]:
        """
        Dynamic fact-driven template synthesis strictly based on E(c) state variables
        and functions without contract name string matching.
        """
        properties: List[Property] = []
        chunk_map = {c.id: c for c in evidence_chunks}
        chunk_ids = list(chunk_map.keys())

        # 1. Smart Account Properties
        if facts.has_role(Role.ACCOUNT):
            has_session = any(sv.role_tag == "session_key_map" for sv in facts.state_variables)
            has_target = any(sv.role_tag == "allowed_target_map" for sv in facts.state_variables)
            has_expiry = any(sv.role_tag == "expiry_map" for sv in facts.state_variables)

            val_df = next(
                (df for df in facts.data_flows if df.function_name == "validateUserOp"), None
            )

            # Check if allowedTarget exists but is NOT read during validation
            if has_session and has_target and val_df and "allowedTarget" not in val_df.state_vars_read:
                session_sources = [cid for cid, c in chunk_map.items() if c.topic in ["authorization", "session key"]]
                properties.append(
                    Property(
                        property_id=_stable_prop_id(
                            "PROP-SESSION-TARGET", "SESSION", "Account",
                            "success(validateUserOp(op)) AND signedBySessionKey(op, K)",
                            "target(op) == allowedTarget[K]",
                        ),
                        template_type=PropertyType.SESSION,
                        target_role=Role.ACCOUNT,
                        bindings=PropertyBinding(
                            validator_function="validateUserOp",
                            key_mapping="sessionKey",
                            target_policy_mapping="allowedTarget",
                            target_expression="op.callData.target",
                        ),
                        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
                        required_condition="target(op) == allowedTarget[K]",
                        source_chunk_ids=session_sources,
                    )
                )

            # Check if sessionExpiry exists but is NOT read during validation
            if has_expiry and val_df and not any(var in val_df.state_vars_read for var in ["sessionExpiry", "expiry"]):
                expiry_sources = [cid for cid, c in chunk_map.items() if c.topic == "session key"]
                properties.append(
                    Property(
                        property_id=_stable_prop_id(
                            "PROP-SESSION-EXPIRY", "SESSION", "Account",
                            "success(validateUserOp(op)) AND signedBySessionKey(op, K)",
                            "notExpired(K)",
                        ),
                        template_type=PropertyType.SESSION,
                        target_role=Role.ACCOUNT,
                        bindings=PropertyBinding(
                            validator_function="validateUserOp",
                            key_mapping="sessionKey",
                            custom_bindings={"expiry_mapping": "sessionExpiry"},
                        ),
                        precondition="success(validateUserOp(op)) AND signedBySessionKey(op, K)",
                        required_condition="notExpired(K)",
                        source_chunk_ids=expiry_sources,
                    )
                )

            # Nonce Property
            nonce_sources = [cid for cid, c in chunk_map.items() if c.topic == "nonce"]
            properties.append(
                Property(
                    property_id=_stable_prop_id(
                        "PROP-NONCE", "NONCE", "Account",
                        "success(validateUserOp(op))",
                        "nonceFresh(op)",
                    ),
                    template_type=PropertyType.NONCE,
                    target_role=Role.ACCOUNT,
                    bindings=PropertyBinding(validator_function="validateUserOp"),
                    precondition="success(validateUserOp(op))",
                    required_condition="nonceFresh(op)",
                    source_chunk_ids=nonce_sources,
                )
            )

        # 2. Paymaster Properties
        if facts.has_role(Role.PAYMASTER):
            has_coupon = any(sv.role_tag == "used_coupon_map" for sv in facts.state_variables)
            val_df = next(
                (df for df in facts.data_flows if df.function_name == "validatePaymasterUserOp"), None
            )

            paymaster_sources = [
                cid for cid, c in chunk_map.items() if c.topic == "sponsorship"
            ]

            if has_coupon and val_df and "usedCoupon" not in val_df.state_vars_read:
                properties.append(
                    Property(
                        property_id=_stable_prop_id(
                            "PROP-PAYMASTER-REPLAY", "PAYMASTER", "Paymaster",
                            "success(validatePaymasterUserOp(op))",
                            "validCoupon(op) AND NOT used(op.coupon)",
                        ),
                        template_type=PropertyType.PAYMASTER,
                        target_role=Role.PAYMASTER,
                        bindings=PropertyBinding(
                            validator_function="validatePaymasterUserOp",
                            used_coupon_mapping="usedCoupon",
                            sponsor_variable="sponsor",
                        ),
                        precondition="success(validatePaymasterUserOp(op))",
                        required_condition="validCoupon(op) AND NOT used(op.coupon)",
                        source_chunk_ids=paymaster_sources,
                    )
                )

        # 3. Validation Scope Properties
        scope_sources = [
            cid for cid, c in chunk_map.items() if c.topic == "validation scope"
        ]
        if scope_sources:
            properties.append(
                Property(
                    property_id=_stable_prop_id(
                        "PROP-SCOPE",
                        "SCOPE",
                        facts.roles[0].value if facts.roles else "Account",
                        "simulatingValidation(op)",
                        "NOT forbiddenOpcodeExecuted(tr) AND NOT externalStorageAccessed(tr)",
                    ),
                    template_type=PropertyType.SCOPE,
                    target_role=facts.roles[0] if facts.roles else Role.ACCOUNT,
                    bindings=PropertyBinding(
                        validator_function="validatePaymasterUserOp"
                        if facts.has_role(Role.PAYMASTER)
                        else "validateUserOp"
                    ),
                    precondition="simulatingValidation(op)",
                    required_condition="NOT forbiddenOpcodeExecuted(tr) AND NOT externalStorageAccessed(tr)",
                    source_chunk_ids=scope_sources,
                )
            )

        return properties
