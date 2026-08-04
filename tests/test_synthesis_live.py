# SPDX-License-Identifier: MIT
"""
Live Integration Test Suite for SpecGuard-AA Property Synthesis (Part D.2).
Automatically skips when no ANTHROPIC_API_KEY or OPENAI_API_KEY is configured in .env.
"""

import os
import pytest
from dotenv import load_dotenv

from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_queries
from specguard.retrieval.retriever import HybridRetriever
from specguard.synthesis.synthesizer import PropertySynthesizer

load_dotenv()

HAS_KEY = bool(
    (os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_API_KEY").strip())
    or (os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_API_KEY").strip())
)

SESSION_ACCOUNT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SessionAccount.sol"
)
EXPIRY_SESSION_PATH = os.path.join(
    "contracts", "src", "worked_examples", "ExpirySessionAccount.sol"
)


@pytest.mark.skipif(not HAS_KEY, reason="No live LLM API key configured in environment or .env file")
def test_live_synthesis_session_account():
    facts = extract_facts(SESSION_ACCOUNT_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    evidence = HybridRetriever(corpus).retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer(live=True)
    prompt = synthesizer.get_llm_prompt(facts, evidence)
    
    # Confirm raw API key is NEVER present in prompt
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key and anthropic_key.strip():
        assert anthropic_key.strip() not in prompt

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and openai_key.strip():
        assert openai_key.strip() not in prompt

    props = synthesizer.synthesize(facts, evidence, force_live=True)
    assert len(props) > 0, "Live synthesis must produce candidate properties"


@pytest.mark.skipif(not HAS_KEY, reason="No live LLM API key configured in environment or .env file")
def test_live_synthesis_expiry_session_account():
    facts = extract_facts(EXPIRY_SESSION_PATH)
    corpus = load_corpus("corpus")
    queries = build_queries(facts)
    evidence = HybridRetriever(corpus).retrieve_all_for_contract(queries, facts)

    synthesizer = PropertySynthesizer(live=True)
    props = synthesizer.synthesize(facts, evidence, force_live=True)
    assert len(props) > 0
