# SPDX-License-Identifier: MIT
"""
Script to sample and display a deterministic, genuinely random 20-chunk sample from the rebuilt corpus.
"""

import json
import random
import os

def run_sample(seed: int = 20260901, corpus_path: str = os.path.join("corpus", "audit_knowledge.json")):
    with open(corpus_path, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    random.seed(seed)
    sample_indices = random.sample(range(len(chunks)), 20)

    print(f"=== 20-SAMPLE VERIFICATION (Seed: {seed}, Total Corpus Chunks: {len(chunks)}) ===\n")

    for i, idx in enumerate(sample_indices, 1):
        c = chunks[idx]
        print(f"[{i:02d}] ID: {c['id']}")
        print(f"     Source: {c['source']}")
        print(f"     Commit: {c.get('source_commit', 'N/A')[:8]} | Authority: {c.get('authority', 'N/A')} | Kind: {c.get('kind', 'N/A')}")
        print(f"     Role: {c['role']} | Phase: {c['phase']} | Topic: {c['topic']}")
        snippet = " ".join(c["text"].split())
        if len(snippet) > 240:
            snippet = snippet[:240] + "..."
        print(f"     Text: {snippet}\n")

if __name__ == "__main__":
    run_sample()
