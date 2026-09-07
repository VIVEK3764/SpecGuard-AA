# SPDX-License-Identifier: MIT
"""
Model-Driven Property Synthesis Engine for SpecGuard-AA (Phase E).
Translates retrieved normative obligations into formal candidate properties
using pure predicate grammar and disjoint few-shot examples without variable leakage.
Eliminates hardcoded detectors and arbitrary canned fallbacks.
"""

import os
import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field

from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
)
from specguard.retrieval.corpus import CorpusChunk
from specguard.synthesis.few_shot_examples import format_disjoint_few_shots

CACHE_DIR = os.path.join(".cache", "llm_synthesis")
os.makedirs(CACHE_DIR, exist_ok=True)

# Pure Predicate Grammar Specification (Step E2: zero semantic examples tied to benchmark variables)
PREDICATE_GRAMMAR_TEXT = """Allowed predicates (name, arity, argument sorts):
  success(validationResult) -> bool
  signedBy(op, key) -> bool
  commits(digest, field) -> bool
  memberOf(key, mapping) -> bool
  equals(expr, expr) -> bool
  before(timeExpr, timeExpr) -> bool
  reads(trace, storageSlot) -> bool
  executes(trace, opcode) -> bool"""

ALLOWED_PREDICATE_NAMES = {
    "success", "signedBy", "commits", "memberOf", "equals",
    "before", "reads", "executes", "NOT", "AND", "OR", "true", "false",
}

PROMPT_TEMPLATE = """System: You are SpecGuard-AA, a formal specification translation engine for ERC-4337 Account Abstraction smart contracts.
Your task is to translate a single normative obligation into a checkable formal candidate security property for the target contract, or return an empty list if the obligation does not apply or cannot be expressed.

Retrieved Normative Obligation:
ID: {obligation_id}
Statement: "{obligation_statement}"

Extracted Contract Facts E(c):
{facts_json}

Supporting Evidence Chunks C:
{evidence_json}

CRITICAL CONSTRAINTS:
1. You MUST select 'template_type' ONLY from: 'SESSION', 'PAYMASTER', 'AUTH', 'NONCE', 'SCOPE'.
2. For citations, you MUST cite the 'id' field of the chunks provided in the evidence block above.
3. Predicate Grammar:
{grammar_text}

{few_shot_section}

Output structured properties matching the requested schema. Return a JSON array of candidate properties, or an empty JSON array [] if this obligation does not apply to the contract."""


class PropertySynthesizer:
    """
    Translates retrieved normative obligations into formal candidate properties.
    Executes real LLM API calls with persistent cache. Zero hardcoded canned detectors.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        live: bool = False,
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.model = model or os.getenv("LLM_MODEL") or ("gpt-4o" if self.provider == "openai" else "claude-3-5-sonnet-20241022")
        self.live = live

        if api_key:
            self.api_key = api_key
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
        else:
            self.api_key = None

    def synthesize(
        self,
        facts: ContractFacts,
        evidence_chunks: List[CorpusChunk],
        force_live: bool = False,
        mode: str = "full_specguard",
        obligation_id: str = "OBL-AA-001",
        obligation_statement: str = "An authorized signature must authenticate the user operation.",
    ) -> List[Property]:
        """
        Synthesizes candidate properties from facts and retrieved evidence for a given obligation.
        Zero hardcoded rule fallback. Fails explicitly if model is unavailable and no cached response exists.
        """
        is_live = self.live or force_live
        has_key = bool(self.api_key and self.api_key.strip())

        cache_key = self._get_cache_key(facts, evidence_chunks, obligation_id, mode)
        cache_path = os.path.join(CACHE_DIR, f"{cache_key}.json")

        # 1. Check cache first
        if os.path.exists(cache_path) and not is_live:
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                if isinstance(cached_data, list):
                    return [Property(**p) for p in cached_data]
                return [Property(**p) for p in cached_data.get("properties", [])]
            except Exception as e:
                print(f"[-] Cache read error: {e}")

        # 2. If model execution unavailable and no cache, fail explicitly per Step E1 Rule 2
        if not has_key and not os.path.exists(cache_path):
            raise RuntimeError(
                f"LLM synthesis unavailable: No API key provided for '{self.provider}' and no valid cached response found. "
                "Pipeline requires model synthesis and cannot silently substitute canned answers."
            )

        # 3. Execute LLM call
        raw_properties = self._synthesize_llm(
            facts, evidence_chunks, obligation_id, obligation_statement, cache_key, cache_path
        )
        return raw_properties

    def _get_cache_key(
        self, facts: ContractFacts, evidence_chunks: List[CorpusChunk], obligation_id: str, mode: str
    ) -> str:
        chunk_ids = sorted([c.id for c in evidence_chunks])
        raw_key = f"{facts.contract_name}:{facts.source_path}:{obligation_id}:{','.join(chunk_ids)}:{self.model}:{mode}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def _synthesize_llm(
        self,
        facts: ContractFacts,
        evidence_chunks: List[CorpusChunk],
        obligation_id: str,
        obligation_statement: str,
        cache_key: str,
        cache_path: str,
    ) -> List[Property]:
        """Executes LLM API call per obligation and caches structured response."""
        facts_payload = {
            "contract_name": facts.contract_name,
            "roles": [r.value for r in facts.roles],
            "mechanisms": [m.tag for m in facts.mechanism_tags],
            "state_variables": [
                {"name": sv.name, "type": sv.type_str, "role_tag": sv.role_tag}
                for sv in facts.state_variables
            ],
            "functions": [
                {"name": fn.name, "state_vars_read": fn.state_variables_read}
                for fn in facts.functions
            ],
            "data_flows": [
                {
                    "function": df.function_name,
                    "reads": df.state_vars_read,
                    "unread_in_validation": getattr(df, "unread_in_validation", []),
                }
                for df in facts.data_flows
            ],
        }

        evidence_payload = [
            {"id": c.id, "topic": c.topic, "text": c.text[:400], "authority": c.authority}
            for c in evidence_chunks[:5]
        ]

        prompt = PROMPT_TEMPLATE.format(
            obligation_id=obligation_id,
            obligation_statement=obligation_statement,
            facts_json=json.dumps(facts_payload, indent=2),
            evidence_json=json.dumps(evidence_payload, indent=2),
            grammar_text=PREDICATE_GRAMMAR_TEXT,
            few_shot_section=format_disjoint_few_shots(),
        )

        response_text = ""
        if self.provider == "openai" and self.api_key:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a formal specification synthesis engine."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
            )
            response_text = resp.choices[0].message.content or ""
        elif self.provider == "anthropic" and self.api_key:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            resp = client.messages.create(
                model=self.model,
                max_tokens=1500,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}],
            )
            response_text = resp.content[0].text if resp.content else ""
        else:
            raise RuntimeError(f"Unsupported or unconfigured provider '{self.provider}'")

        # Parse JSON from response
        properties = self._parse_llm_response(response_text)

        # Cache response
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump({"properties": [p.model_dump() for p in properties]}, f, indent=2)

        return properties

    def _parse_llm_response(self, text: str) -> List[Property]:
        """Parses model response into Property objects."""
        # Find json block
        match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
        raw_json = match.group(1) if match else text.strip()

        try:
            items = json.loads(raw_json)
            if not isinstance(items, list):
                items = [items]
            results = []
            for it in items:
                results.append(Property(**it))
            return results
        except Exception:
            return []
