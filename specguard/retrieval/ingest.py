# SPDX-License-Identifier: MIT
"""
High-Scale Audit Finding Corpus Builder & Ingestion Engine (Step C1).
Parses real git-cloned audit reports from Code4rena, Sherlock, and Pashov Audit Group.
Segregates findings into description and recommendation chunks with normative modal quality filtering.
"""

import os
import re
import json
import glob
import subprocess
from typing import List, Dict, Any, Tuple, Optional
from specguard.retrieval.corpus import CorpusChunk

NORMATIVE_MODALS = re.compile(
    r"\b(must|should|shall|must not|cannot|require|required|revert|reverts|enforce|enforces|validate|validates|ensure|ensures|prevent|prevents|restrict|restricts|bound|bounds|check|checks|guarantee|prohibit|prohibits)\b",
    re.IGNORECASE,
)

BOILERPLATE_PATTERNS = [
    re.compile(r"yarn (install|add|test)", re.IGNORECASE),
    re.compile(r"git clone https://", re.IGNORECASE),
    re.compile(r"## Table of contents", re.IGNORECASE),
    re.compile(r"## Wardens\s+\d+\s+Wardens", re.IGNORECASE),
    re.compile(r"A C4 audit contest is an event in which community participants", re.IGNORECASE),
    re.compile(r"Pashov Audit Group consists of multiple teams of some of the best", re.IGNORECASE),
    re.compile(r"A smart contract security review can never verify the complete absence", re.IGNORECASE),
    re.compile(r"hardhat deploy --network", re.IGNORECASE),
    re.compile(r"## About C4", re.IGNORECASE),
    re.compile(r"## Severity Criteria", re.IGNORECASE),
]


def is_boilerplate(text: str) -> bool:
    """Detect if chunk contains navigation chrome, readme setup, or contest boilerplate."""
    if len(text.strip()) < 80:
        return True
    for bp in BOILERPLATE_PATTERNS:
        if bp.search(text):
            return True
    return False


def get_git_commit(repo_path: str) -> str:
    """Retrieve git HEAD commit hash for a cloned repo."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def extract_sections_from_markdown(md_text: str) -> List[Tuple[str, str, str]]:
    """
    Parse markdown report into individual findings: (finding_title, description_text, recommendation_text).
    """
    findings = []
    
    # Split on finding headers:
    # ## [[H-01] Title] or # [H-01] Title or ## [M-01] Title or ## Issue H-1: Title or ### [CRIT-01] Title
    finding_split = re.split(
        r"(?m)^(?=#{1,3}\s+\[?(?:(?:\[[HMLQC]-\d+\])|(?:[HMLQC]-\d+)|(?:HIGH-\d+)|(?:MED-\d+)|(?:LOW-\d+)|(?:CRIT-\d+)|(?:Issue\s+[HMLC]-\d+))[^\]\n]+\]?)",
        md_text
    )
    
    for block in finding_split:
        block = block.strip()
        if not block or len(block) < 100:
            continue
        
        lines = block.splitlines()
        header = lines[0].strip("# \t[]*")
        
        desc_parts = []
        rec_parts = []
        in_rec = False
        
        for line in lines[1:]:
            if re.search(r"^#{2,4}\s+(Recommended Mitigation|Recommendation|Remediation|Mitigation|Recommended Fix)", line, re.IGNORECASE):
                in_rec = True
                continue
            elif re.search(r"^#{2,4}\s+(Discussion|Sponsor|Judge|Assessed|Lines of code|Vulnerability details|Proof of Concept)", line, re.IGNORECASE) and in_rec:
                break
            
            if in_rec:
                rec_parts.append(line)
            else:
                desc_parts.append(line)
                
        desc_text = "\n".join(desc_parts).strip()
        rec_text = "\n".join(rec_parts).strip()
        
        # If no explicit recommendation header was found, take the last paragraph if it has modal verbs
        if not rec_text and desc_text:
            paragraphs = [p.strip() for p in desc_text.split("\n\n") if p.strip()]
            if len(paragraphs) > 1 and NORMATIVE_MODALS.search(paragraphs[-1]):
                rec_text = paragraphs[-1]
                desc_text = "\n\n".join(paragraphs[:-1])
        
        if desc_text or rec_text:
            findings.append((header, desc_text, rec_text))
            
    return findings


def determine_role_and_phase(text: str) -> Tuple[str, str, str]:
    """Classify finding role, phase, and topic based on keywords."""
    t = text.lower()
    
    # Role
    if "paymaster" in t or "sponsor" in t or "coupon" in t:
        role = "paymaster"
    elif "factory" in t or "createsender" in t or "deployaccount" in t:
        role = "factory"
    elif "account" in t or "wallet" in t or "session" in t or "validator" in t or "signature" in t:
        role = "account"
    else:
        role = "generic"
        
    # Phase
    if "postop" in t:
        phase = "postOp"
    elif "validate" in t or "signature" in t or "recovery" in t or "ecrecover" in t or "nonce" in t or "digest" in t:
        phase = "validation"
    elif "exec" in t or "execute" in t or "fallback" in t:
        phase = "execution"
    else:
        phase = "validation"
        
    # Topic
    if "session" in t or "delegat" in t or "policy" in t:
        topic = "session key"
    elif "digest" in t or "chainid" in t or "replay" in t or "domain" in t or "eip-712" in t or "hash collision" in t:
        topic = "digest commitment"
    elif "coupon" in t or "postop" in t or "consumption" in t:
        topic = "coupon sponsorship"
    elif "webauthn" in t or "passkey" in t or "p256" in t or "r1" in t:
        topic = "webauthn passkey"
    elif "module" in t or "hook" in t or "erc-7579" in t or "registry" in t:
        topic = "module management"
    elif "scope" in t or "opcode" in t or "storage" in t or "timestamp" in t:
        topic = "validation scope"
    else:
        topic = "authorization"
        
    return role, phase, topic


def ingest_all_repos(repos_dir: str = os.path.join("scratch", "repos")) -> Tuple[List[CorpusChunk], int, int]:
    """
    Ingest all cloned audit repositories. Returns (valid_chunks, pre_filter_count, post_filter_count).
    """
    pre_filter_count = 0
    valid_chunks: List[CorpusChunk] = []
    
    if not os.path.exists(repos_dir):
        print(f"[-] Repos directory {repos_dir} does not exist!")
        return valid_chunks, 0, 0
        
    repo_dirs = [os.path.join(repos_dir, d) for d in os.listdir(repos_dir) if os.path.isdir(os.path.join(repos_dir, d))]
    
    for repo in repo_dirs:
        repo_name = os.path.basename(repo)
        commit = get_git_commit(repo)
        
        target_mds = []
        if repo_name == "pashov_audits":
            target_mds = glob.glob(os.path.join(repo, "team", "md", "*.md")) + glob.glob(os.path.join(repo, "solo", "*.md"))
        else:
            # Code4rena or Sherlock repos: target report.md or README.md
            rep = os.path.join(repo, "report.md")
            rdm = os.path.join(repo, "README.md")
            if os.path.exists(rep):
                target_mds.append(rep)
            elif os.path.exists(rdm):
                target_mds.append(rdm)
            else:
                target_mds = glob.glob(os.path.join(repo, "*.md"))
                
        print(f"[+] Processing {repo_name}: {len(target_mds)} report files (commit {commit[:8]})...")
        
        global_chunk_counter = 0
        sanitized_repo = re.sub(r"[^A-Z0-9]", "", repo_name.upper())[:18]
        for md_path in target_mds:
            try:
                with open(md_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue
                
            findings = extract_sections_from_markdown(content)
            
            for idx, (title, desc, rec) in enumerate(findings):
                base_name = os.path.splitext(os.path.basename(md_path))[0]
                
                # 1. Description Chunk
                if desc:
                    pre_filter_count += 1
                    if not is_boilerplate(desc) and NORMATIVE_MODALS.search(desc):
                        global_chunk_counter += 1
                        role, phase, topic = determine_role_and_phase(desc)
                        c_id = f"AUDIT-{sanitized_repo}-{global_chunk_counter:04d}-DESC"
                        valid_chunks.append(
                            CorpusChunk(
                                id=c_id,
                                source=f"{title} (Description) - {base_name}",
                                role=role,
                                phase=phase,
                                topic=topic,
                                text=desc[:3000],
                                authority=0.85,
                                version_scope=["0.6", "0.7", "0.8"],
                                source_url=f"https://github.com/code-423n4/{repo_name}",
                                source_commit=commit,
                                kind="description",
                            )
                        )
                        
                # 2. Recommendation Chunk (carries high normative requirement density!)
                if rec:
                    pre_filter_count += 1
                    if not is_boilerplate(rec) and NORMATIVE_MODALS.search(rec):
                        global_chunk_counter += 1
                        role, phase, topic = determine_role_and_phase(rec)
                        c_id = f"AUDIT-{sanitized_repo}-{global_chunk_counter:04d}-REC"
                        valid_chunks.append(
                            CorpusChunk(
                                id=c_id,
                                source=f"{title} (Recommendation) - {base_name}",
                                role=role,
                                phase=phase,
                                topic=topic,
                                text=rec[:3000],
                                authority=0.90,
                                version_scope=["0.6", "0.7", "0.8"],
                                source_url=f"https://github.com/code-423n4/{repo_name}",
                                source_commit=commit,
                                kind="recommendation",
                            )
                        )

    post_filter_count = len(valid_chunks)
    return valid_chunks, pre_filter_count, post_filter_count


def clean_standards_yaml_frontmatter(corpus_dir: str = "corpus") -> None:
    """Strip leading YAML frontmatter from standards JSON files if present."""
    for fn in ["erc4337.json", "erc7562.json"]:
        path = os.path.join(corpus_dir, fn)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                items = json.load(f)
            cleaned = []
            for it in items:
                text = it.get("text", "")
                if text.startswith("---"):
                    parts = text.split("---", 2)
                    if len(parts) >= 3:
                        text = parts[2].strip()
                        it["text"] = text
                # Ensure extended fields exist
                if "authority" not in it:
                    it["authority"] = 1.0  # Canonical standards have 1.0 authority
                if "kind" not in it:
                    it["kind"] = "standard"
                if "version_scope" not in it:
                    it["version_scope"] = ["0.6", "0.7", "0.8"]
                cleaned.append(it)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cleaned, f, indent=2)
            print(f"[+] Cleaned YAML frontmatter in {fn}")
        except Exception as e:
            print(f"[-] Error cleaning {fn}: {e}")
