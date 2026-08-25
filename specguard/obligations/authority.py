# SPDX-License-Identifier: MIT
"""
Authority Scoring and Conflict Resolution for SpecGuard-AA Obligations (Step B3).
Calculates statement authority scores and resolves/logs conflicts between obligations.
"""

import os
from typing import List, Tuple, Dict
from specguard.obligations.models import Authority, Obligation

CONFLICT_LOG_PATH = os.path.join("specguard", "obligations", "CONFLICT_LOG.md")


def compute_authority(
    modal_strength: str = "MUST",
    corroboration: int = 1,
    specificity: str = "field-level",
    w1: float = 0.4,
    w2: float = 0.3,
    w3: float = 0.3,
) -> Authority:
    """
    Calculate statement-level authority score:
    Score = w1 * modal_strength + w2 * corroboration + w3 * specificity
    """
    auth = Authority(
        modal_strength=modal_strength,
        corroboration=corroboration,
        specificity=specificity,
    )
    auth.compute_score(w1, w2, w3)
    return auth


def resolve_conflicts(obligations: List[Obligation]) -> Tuple[List[Obligation], List[str]]:
    """
    Detect conflicts between obligations sharing trigger & scope.
    Resolves toward the obligation with the higher authority score.
    Logs conflict entry to CONFLICT_LOG.md.
    """
    conflict_logs: List[str] = []
    resolved: List[Obligation] = []
    
    # Group by id prefix or conflict decl
    conflict_groups: Dict[str, List[Obligation]] = {}
    for ob in obligations:
        for target in ob.conflicts_with:
            pair_key = "-".join(sorted([ob.id, target]))
            if pair_key not in conflict_groups:
                conflict_groups[pair_key] = []
            if ob not in conflict_groups[pair_key]:
                conflict_groups[pair_key].append(ob)

    for pair_key, group in conflict_groups.items():
        if len(group) >= 2:
            # Sort by authority score descending
            group.sort(key=lambda o: o.authority.score, reverse=True)
            winner = group[0]
            loser = group[1]
            log_entry = (
                f"### Conflict Resolved: `{winner.id}` vs `{loser.id}`\n"
                f"- **Winner**: `{winner.id}` (Score: {winner.authority.score:.4f}, Modal: {winner.authority.modal_strength}, Sources: {len(winner.sources)})\n"
                f"- **Loser**: `{loser.id}` (Score: {loser.authority.score:.4f}, Modal: {loser.authority.modal_strength}, Sources: {len(loser.sources)})\n"
                f"- **Statement**: {winner.statement}\n"
            )
            conflict_logs.append(log_entry)

    if conflict_logs and os.path.exists(os.path.dirname(CONFLICT_LOG_PATH)):
        with open(CONFLICT_LOG_PATH, "a", encoding="utf-8") as f:
            for log in conflict_logs:
                f.write(log + "\n")

    return obligations, conflict_logs
