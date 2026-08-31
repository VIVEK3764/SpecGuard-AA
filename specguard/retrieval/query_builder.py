# SPDX-License-Identifier: MIT
"""
Multi-View Query Builder for SpecGuard-AA (Step C3).
Constructs MultiViewQuery separating PRESENT (code-extracted mechanism tags)
and IMPLIED (normative obligation topics and probes from TRIGGER_MAP).
Includes mechanical ablation toggle for IMPLIED view.
"""

from dataclasses import dataclass, field
from typing import List, Set, Tuple, Dict, Any, Optional
from specguard.models import ContractFacts, Role
from specguard.retrieval.trigger_map import get_topics_and_probes_for_mechanisms, TRIGGER_MAP


@dataclass
class MultiViewQuery:
    present: Set[str] = field(default_factory=set)          # Mechanism tags directly in M(c)
    implied: Set[str] = field(default_factory=set)          # Normative topics & probes from TRIGGER_MAP[m]
    role_phase: Tuple[str, str] = ("generic", "validation") # Hard filter: (target_role, target_phase)
    environment: Dict[str, Any] = field(default_factory=lambda: {"version": "0.7"}) # Hard filter
    contract_name: str = ""

    def get_present_query_text(self) -> str:
        """Textual query for the PRESENT view (code-level structural features, rename-invariant)."""
        terms = []
        role, phase = self.role_phase
        if role != "generic":
            terms.append(role)
        terms.append(phase)
        terms.extend(sorted(list(self.present)))
        return " ".join(terms)

    def get_implied_query_texts(self) -> List[str]:
        """List of search probes for the IMPLIED view."""
        return list(self.implied)


def build_multiview_query(
    facts: ContractFacts,
    protocol_version: str = "0.7",
    enable_implied: bool = True,
) -> MultiViewQuery:
    """
    Construct a MultiViewQuery for a contract.
    enable_implied: Mechanical toggle. When False, reduces to PRESENT view only.
    """
    # 1. Determine Role and Phase
    role = "generic"
    if facts.has_role(Role.ACCOUNT):
        role = "account"
    elif facts.has_role(Role.PAYMASTER):
        role = "paymaster"
    elif facts.has_role(Role.FACTORY):
        role = "factory"

    phase = "validation"

    # 2. Extract PRESENT View (Mechanisms in M(c))
    present_tags: Set[str] = {m.tag for m in facts.mechanism_tags}

    # 3. Extract IMPLIED View (Normative topics & search probes from TRIGGER_MAP)
    implied_probes: Set[str] = set()
    if enable_implied:
        topics, probes = get_topics_and_probes_for_mechanisms(list(present_tags))
        implied_probes.update(probes)

    return MultiViewQuery(
        present=present_tags,
        implied=implied_probes,
        role_phase=(role, phase),
        environment={"version": protocol_version},
        contract_name=facts.contract_name,
    )


# Backward-compatibility adapter
class RetrievalQuery:
    def __init__(self, query_text: str, target_role: str = "generic", target_phase: str = "validation", topic: str = "general"):
        self.query_text = query_text
        self.target_role = target_role
        self.target_phase = target_phase
        self.topic = topic


def build_queries(facts: ContractFacts) -> List[RetrievalQuery]:
    """Compatibility adapter generating flat query list from MultiViewQuery."""
    mvq = build_multiview_query(facts, enable_implied=True)
    queries = [
        RetrievalQuery(
            query_text=mvq.get_present_query_text(),
            target_role=mvq.role_phase[0],
            target_phase=mvq.role_phase[1],
            topic="present_mechanisms",
        )
    ]
    for probe in mvq.implied:
        queries.append(
            RetrievalQuery(
                query_text=probe,
                target_role=mvq.role_phase[0],
                target_phase=mvq.role_phase[1],
                topic="implied_obligation",
            )
        )
    return queries
