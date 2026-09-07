import re
import json
from specguard.extractor import extract_facts
from specguard.synthesis.synthesizer import PropertySynthesizer, PROMPT_TEMPLATE, PREDICATE_GRAMMAR_TEXT
from specguard.synthesis.few_shot_examples import format_disjoint_few_shots
from specguard.retrieval.corpus import CorpusChunk

# 1. Extract facts for SessionAccount
facts = extract_facts("benchmark/stage1_fact_extraction/contracts/SessionAccount.sol")

# Evidence chunk (generic test chunk)
evidence = [
    CorpusChunk(
        id="CHUNK-RETRIEVED-001",
        source="Retrieved Standard",
        text="A delegated session key must only interact with specified target addresses.",
        section="Session Keys",
        authority=0.9,
        topic="authorization"
    )
]

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
    for c in evidence[:5]
]

prompt = PROMPT_TEMPLATE.format(
    obligation_id="SES-001",
    obligation_statement="A delegated key must be restricted to a set of permitted target addresses.",
    facts_json=json.dumps(facts_payload, indent=2),
    evidence_json=json.dumps(evidence_payload, indent=2),
    grammar_text=PREDICATE_GRAMMAR_TEXT,
    few_shot_section=format_disjoint_few_shots(),
)

print("=" * 80)
print("AUDIT OF REBUILT SYNTHESIS PROMPT (STEP E2)")
print("=" * 80)

# Check 1: Check if prompt template or grammar has forbidden variable names
forbidden_vars = ["allowedTarget", "usedCoupon", "sessionExpiry"]
leakages = []
for fv in forbidden_vars:
    # Only check prompt template, grammar, few-shots, obligation (excluding facts_payload which is contract's own source)
    if fv in PROMPT_TEMPLATE:
        leakages.append(f"Found {fv} in PROMPT_TEMPLATE")
    if fv in PREDICATE_GRAMMAR_TEXT:
        leakages.append(f"Found {fv} in PREDICATE_GRAMMAR_TEXT")
    if fv in format_disjoint_few_shots():
        leakages.append(f"Found {fv} in format_disjoint_few_shots()")

print(f"1. Prompt instructions leakage check: {len(leakages)} leaks found.")
for lk in leakages:
    print(f"   [!] {lk}")

# Check 2: Check for corpus chunk IDs in prompt template / grammar / few shots
corpus_chunk_pattern = r"(ERC7562-[A-Z]+-\d+|ERC4337-[A-Z]+-\d+|AUDIT-[A-Za-z0-9-]+)"
chunk_leaks = re.findall(corpus_chunk_pattern, PROMPT_TEMPLATE + PREDICATE_GRAMMAR_TEXT + format_disjoint_few_shots())
print(f"2. Corpus chunk ID leakage check in instructions: {len(chunk_leaks)} leaks found: {chunk_leaks}")

# Check 3: Check predicate grammar
print("\n3. Predicate grammar text in prompt:")
for line in PREDICATE_GRAMMAR_TEXT.strip().split("\n"):
    print(f"   {line}")

# Check 4: Few-shot examples check
print("\n4. Disjoint few-shot examples in prompt:")
for line in format_disjoint_few_shots().strip().split("\n")[:20]:
    print(f"   {line}")

print("\n" + "=" * 80)
print("FULL PROMPT TEXT:")
print("=" * 80)
print(prompt)
