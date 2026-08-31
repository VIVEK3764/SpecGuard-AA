# SPDX-License-Identifier: MIT
"""
Per-Obligation Sentence-Level Grounding Engine for SpecGuard-AA (Step C5).
Validates that cited evidence chunks contain normative modals in the SAME SENTENCE
as predicate lexicon terms. Discards ungrounded conjuncts and properties with zero fallbacks.
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from pydantic import BaseModel
from specguard.models import Property, PropertyType
from specguard.retrieval.corpus import CorpusChunk

# Normative Modals required in the exact same sentence
NORMATIVE_MODALS = re.compile(
    r"\b(must|should|shall|require|requires|required|enforce|enforces|enforced|revert|reverts|reverting|"
    r"guarantee|guarantees|guaranteed|ensure|ensures|ensured|prevent|prevents|prevented|"
    r"restrict|restricts|restricted|bound|bounds|bounded|validate|validates|validated|check|checks|checked)\b",
    re.IGNORECASE,
)

# Hand-authored predicate lexicon mapping predicate symbols/themes to domain vocabulary
PREDICATE_LEXICON: Dict[str, Set[str]] = {
    "commits": {
        "hash", "digest", "chainid", "entrypoint", "nonce", "sender", "calldata",
        "replay", "domain separator", "domain separation", "eip-712", "eip712", "recover",
        "signature covers", "signed message", "userophash", "packeduseroperation",
    },
    "allowedtarget": {
        "target", "whitelist", "allowlist", "contract restriction", "selector",
        "permitted", "destination", "policy", "scope", "bound", "allowed", "destination contract",
    },
    "validcoupon": {
        "coupon", "single use", "consumed", "consumption", "sponsor", "postop",
        "ordering", "paymaster", "voucher", "discount", "reimbursement", "double spend",
    },
    "expiry": {
        "validuntil", "validafter", "expiration", "timestamp", "expiry", "time window",
        "time range", "deadline", "duration", "expired", "time-bound",
    },
    "webauthn": {
        "webauthn", "clientdatajson", "authenticator", "challenge", "secp256r1",
        "p-256", "p256", "user presence", "passkey", "r1 curve",
    },
    "signedby": {
        "signature", "signer", "ecrecover", "owner", "authorized", "validuserop",
        "account", "permission", "authorization", "session key", "delegated key",
    },
    "nonce": {
        "nonce", "replay", "sequence", "counter", "invalidation", "used", "uniquely",
    },
    "scope": {
        "storage", "frame", "opcode", "forbidden", "boundary", "external call",
        "validation phase", "stake", "reputation",
    },
}


class GroundingRejection(BaseModel):
    property_id: str
    template_type: str
    conjunct: str
    cited_chunk_id: str
    reason: str


class SentenceLevelGroundingEngine:
    """
    Performs sentence-level co-occurrence checking between predicate terms and normative modals.
    Rejects claims where citations do not normative co-occur in the same sentence.
    """

    def __init__(self):
        self.rejection_log: List[GroundingRejection] = []

    def split_into_sentences(self, text: str) -> List[str]:
        """Split text into sentences cleanly."""
        raw_sentences = re.split(r"(?<=[.!?\n])\s+", text)
        return [s.strip() for s in raw_sentences if len(s.strip()) > 10]

    def extract_conjuncts(self, condition: str) -> List[str]:
        """Extract individual conjunct clauses from a condition string."""
        clauses = re.split(r"\s+AND\s+|\s+&&\s+", condition, flags=re.IGNORECASE)
        return [c.strip() for c in clauses if c.strip()]

    def get_lexicon_terms_for_conjunct(self, conjunct: str, template_type: PropertyType) -> Set[str]:
        """Find matching predicate lexicon terms for a given conjunct."""
        c_lower = conjunct.lower()
        terms: Set[str] = set()

        if "signedby" in c_lower or "auth" in c_lower:
            terms.update(PREDICATE_LEXICON["signedby"])
        if "allowedtarget" in c_lower or "target" in c_lower or "scope" in c_lower:
            terms.update(PREDICATE_LEXICON["allowedtarget"])
        if "coupon" in c_lower or "consumed" in c_lower:
            terms.update(PREDICATE_LEXICON["validcoupon"])
        if "expiry" in c_lower or "validuntil" in c_lower or "time" in c_lower:
            terms.update(PREDICATE_LEXICON["expiry"])
        if "commit" in c_lower or "digest" in c_lower or "hash" in c_lower:
            terms.update(PREDICATE_LEXICON["commits"])
        if "nonce" in c_lower or "seq" in c_lower:
            terms.update(PREDICATE_LEXICON["nonce"])

        # Fallback to template-type default terms if specific predicate keyword is absent
        if not terms:
            t_str = template_type.value.lower()
            if t_str in ["session", "auth"]:
                terms.update(PREDICATE_LEXICON["signedby"])
            elif t_str == "paymaster":
                terms.update(PREDICATE_LEXICON["validcoupon"])
            elif t_str == "nonce":
                terms.update(PREDICATE_LEXICON["nonce"])
            elif t_str in ["scope", "sim"]:
                terms.update(PREDICATE_LEXICON["scope"])

        return terms

    def check_sentence_cooccurrence(
        self,
        chunk_text: str,
        lexicon_terms: Set[str],
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify that at least one sentence in chunk_text contains BOTH a lexicon term
        AND a normative modal.
        """
        sentences = self.split_into_sentences(chunk_text)
        for s in sentences:
            s_lower = s.lower()
            has_modal = bool(NORMATIVE_MODALS.search(s_lower))
            if not has_modal:
                continue

            has_term = any(term in s_lower for term in lexicon_terms)
            if has_term:
                return True, s

        return False, None

    def validate_property_grounding(
        self,
        prop: Property,
        evidence_chunks: List[CorpusChunk],
    ) -> Tuple[Optional[Property], List[GroundingRejection]]:
        """
        Validate grounding for all conjuncts in prop.required_condition.
        Discards ungrounded conjuncts. Rejects entire property if required_condition becomes empty.
        Returns (grounded_property, local_rejections).
        """
        local_rejections: List[GroundingRejection] = []
        if not prop.source_chunk_ids:
            rej = GroundingRejection(
                property_id=prop.property_id,
                template_type=prop.template_type.value,
                conjunct=prop.required_condition,
                cited_chunk_id="NONE",
                reason="No source chunk IDs cited for property.",
            )
            self.rejection_log.append(rej)
            return None, [rej]

        # Build lookup table for cited chunks
        chunk_map = {c.id: c for c in evidence_chunks}
        cited_chunks = [chunk_map[cid] for cid in prop.source_chunk_ids if cid in chunk_map]

        if not cited_chunks:
            rej = GroundingRejection(
                property_id=prop.property_id,
                template_type=prop.template_type.value,
                conjunct=prop.required_condition,
                cited_chunk_id=",".join(prop.source_chunk_ids),
                reason="None of the cited chunk IDs exist in the retrieved evidence set.",
            )
            self.rejection_log.append(rej)
            return None, [rej]

        conjuncts = self.extract_conjuncts(prop.required_condition)
        grounded_conjuncts: List[str] = []
        grounded_chunk_ids: Set[str] = set()

        for conj in conjuncts:
            lexicon_terms = self.get_lexicon_terms_for_conjunct(conj, prop.template_type)
            conj_supported = False

            for chunk in cited_chunks:
                is_grounded, supporting_sent = self.check_sentence_cooccurrence(chunk.text, lexicon_terms)
                if is_grounded:
                    conj_supported = True
                    grounded_chunk_ids.add(chunk.id)
                    break
                else:
                    # Check why it failed
                    has_term = any(t in chunk.text.lower() for t in lexicon_terms)
                    reason = (
                        f"Chunk '{chunk.id}' contains lexicon terms but lacks normative modal in the SAME sentence."
                        if has_term
                        else f"Chunk '{chunk.id}' does not contain any matching lexicon terms for conjunct '{conj}'."
                    )
                    rej = GroundingRejection(
                        property_id=prop.property_id,
                        template_type=prop.template_type.value,
                        conjunct=conj,
                        cited_chunk_id=chunk.id,
                        reason=reason,
                    )
                    local_rejections.append(rej)
                    self.rejection_log.append(rej)

            if conj_supported:
                grounded_conjuncts.append(conj)

        if not grounded_conjuncts:
            return None, local_rejections

        # Return updated property with only grounded conjuncts and verified citations
        updated_prop = prop.model_copy(deep=True)
        updated_prop.required_condition = " AND ".join(grounded_conjuncts)
        updated_prop.source_chunk_ids = list(grounded_chunk_ids)
        return updated_prop, local_rejections
