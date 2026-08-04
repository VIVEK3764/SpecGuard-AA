# SPDX-License-Identifier: MIT
"""
Corpus Rebuild Script for SpecGuard-AA.
Fetches canonical ERC-4337 and ERC-7562 specs, OpenZeppelin audit writeups,
and Code4rena vulnerability reports via HTTP GET.
Builds section-aware chunks and generates corpus/MANIFEST.json.
"""

import os
import re
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import List, Dict, Any

MANIFEST_PATH = "corpus/MANIFEST.json"
ERC4337_PATH = "corpus/erc4337.json"
ERC7562_PATH = "corpus/erc7562.json"
AUDIT_PATH = "corpus/audit_knowledge.json"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

SOURCES_CONFIG = [
    # Category A: Primary Standards
    {
        "id": "SRC-ERC4337-SPEC",
        "category": "A",
        "name": "ERC-4337 Official Specification (GitHub Raw)",
        "url": "https://raw.githubusercontent.com/ethereum/ERCs/master/ERCS/erc-4337.md",
        "alt_url": "https://eips.ethereum.org/EIPS/eip-4337",
        "target_file": ERC4337_PATH,
    },
    {
        "id": "SRC-ERC7562-SPEC",
        "category": "A",
        "name": "ERC-7562 Official Validation Rules (GitHub Raw Living Version)",
        "url": "https://raw.githubusercontent.com/ethereum/ERCs/master/ERCS/erc-7562.md",
        "alt_url": "https://eips.ethereum.org/EIPS/eip-7562",
        "target_file": ERC7562_PATH,
    },
    # Category B: Reference Implementation & Official Audits
    {
        "id": "SRC-ETH-INFINITISM-README",
        "category": "B",
        "name": "EntryPoint Reference Implementation Spec & Architecture",
        "url": "https://raw.githubusercontent.com/eth-infinitism/account-abstraction/develop/README.md",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-OZ-AA-AUDIT-1",
        "category": "B",
        "name": "OpenZeppelin EF Account Abstraction Audit Report",
        "url": "https://www.openzeppelin.com/news/eth-foundation-account-abstraction-audit",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-OZ-AA-AUDIT-2",
        "category": "B",
        "name": "OpenZeppelin EIP-4337 Incremental Audit Writeup",
        "url": "https://www.openzeppelin.com/news/eip-4337-ethereum-account-abstraction-incremental-audit",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-OZ-AA-AUDIT-3",
        "category": "B",
        "name": "OpenZeppelin ERC-4337 Account Abstraction Incremental Audit",
        "url": "https://www.openzeppelin.com/news/erc-4337-account-abstraction-incremental-audit",
        "target_file": AUDIT_PATH,
    },
    # Category C: Security Knowledge Base & Code4rena Contest Reports
    {
        "id": "SRC-C4-COINBASE",
        "category": "C",
        "name": "Code4rena Coinbase Smart Wallet Security Contest Report",
        "url": "https://raw.githubusercontent.com/code-423n4/2024-03-coinbase-findings/main/README.md",
        "alt_url": "https://code4rena.com/reports/2024-03-coinbase",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-33AUDITS-AA",
        "category": "C",
        "name": "33Audits: Account Abstraction Security for Auditors (Paymaster Replay)",
        "url": "https://33audits.hashnode.dev/account-abstraction-security-for-auditors",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-C4-BICONOMY",
        "category": "C",
        "name": "Code4rena Biconomy Paymaster & Smart Account Security Report",
        "url": "https://raw.githubusercontent.com/code-423n4/2023-01-biconomy-findings/main/README.md",
        "alt_url": "https://code4rena.com/reports/2023-01-biconomy",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-C4-SOULWALLET",
        "category": "C",
        "name": "Code4rena SoulWallet ERC-4337 Account Abstraction Audit Report",
        "url": "https://raw.githubusercontent.com/code-423n4/2023-08-shell-findings/main/README.md",
        "alt_url": "https://code4rena.com/reports/2023-08-shell",
        "target_file": AUDIT_PATH,
    },
    {
        "id": "SRC-C4-LENS",
        "category": "C",
        "name": "Code4rena Lens Protocol Security Audit Report",
        "url": "https://raw.githubusercontent.com/code-423n4/2023-07-lens-findings/main/README.md",
        "alt_url": "https://code4rena.com/reports/2023-07-lens",
        "target_file": AUDIT_PATH,
    },
]


def fetch_url(url: str) -> tuple[str, int, str]:
    """Fetch URL and return (content, status_code, fetch_timestamp)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain,application/json,*/*"},
    )
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status_code = resp.getcode()
            charset = resp.headers.get_content_charset() or "utf-8"
            content = resp.read().decode(charset, errors="replace")
            return content, status_code, timestamp
    except urllib.error.HTTPError as e:
        return f"HTTPError {e.code}: {e.reason}", e.code, timestamp
    except Exception as e:
        return f"Error: {str(e)}", 500, timestamp


def clean_html(html_str: str) -> str:
    """Basic HTML tag stripping for web page content."""
    text = re.sub(r"<script[\s\S]*?</script>", "", html_str, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_erc4337_chunks(raw_text: str) -> List[Dict[str, Any]]:
    """Parse section-aware ERC-4337 chunks from official raw markdown spec text."""
    chunks = []
    sections = re.split(r"\n(?=###?\s+)", raw_text)
    idx = 1

    for sec in sections:
        sec_clean = sec.strip()
        if not sec_clean or len(sec_clean) < 80:
            continue

        header_match = re.match(r"^###?\s+(.+)", sec_clean)
        header = header_match.group(1).strip() if header_match else "ERC-4337 Specification Section"

        role = "account"
        phase = "validation"
        topic = "authorization"

        sec_lower = sec_clean.lower()
        if "paymaster" in sec_lower:
            role = "paymaster"
            topic = "sponsorship"
        elif "factory" in sec_lower or "initcode" in sec_lower or "create2" in sec_lower:
            role = "factory"
            phase = "deployment"
            topic = "factory initialization"
        elif "aggregator" in sec_lower:
            role = "aggregator"
            topic = "authorization"
        elif "nonce" in sec_lower:
            topic = "nonce"
        elif "postop" in sec_lower:
            phase = "postOp"
            topic = "gas"

        snippet = sec_clean.replace("\n", " ")
        if len(snippet) > 600:
            snippet = snippet[:600] + "..."

        chunks.append({
            "id": f"ERC4337-SPEC-{idx:03d}",
            "source": f"ERC-4337 Specification: {header}",
            "role": role,
            "phase": phase,
            "topic": topic,
            "text": snippet,
        })
        idx += 1

    return chunks


def parse_erc7562_chunks(raw_text: str) -> List[Dict[str, Any]]:
    """
    Parse ERC-7562 validation rule chunks from official markdown text.
    Preserves official ERC-7562 rule IDs: AUTH-xxx, OP-xxx, STO-xxx, EREP-xxx, SREP-xxx, etc.
    """
    chunks = []
    # Split text by bullet points or headers containing rule IDs like [AUTH-010], [OP-010], [STO-010], etc.
    rule_blocks = re.findall(
        r"(?:^|\n)(?:[\-\*\d\.]+\s+)?\[?([A-Z]{2,4}-\d{3})\]?:?\s*([^\n]+(?:\n(?!\s*(?:[\-\*\d\.]+\s+)?\[?[A-Z]{2,4}-\d{3}\]?).+)*)",
        raw_text,
    )

    seen_ids = set()
    for rule_id, rule_text in rule_blocks:
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)

        clean_text = rule_text.strip().replace("\n", " ")

        role = "generic"
        phase = "validation"
        topic = "validation scope"

        if rule_id.startswith("AUTH"):
            role = "account"
            topic = "authorization"
        elif rule_id.startswith("PAY") or rule_id.startswith("SREP"):
            role = "paymaster"
            topic = "sponsorship"
        elif rule_id.startswith("STO"):
            topic = "validation storage scope"
        elif rule_id.startswith("OP"):
            topic = "forbidden opcodes"
        elif rule_id.startswith("EREP"):
            topic = "entrypoint scope"

        snippet = f"[{rule_id}] {clean_text}"
        if len(snippet) > 600:
            snippet = snippet[:600] + "..."

        chunks.append({
            "id": f"ERC7562-{rule_id}",
            "rule_id": rule_id,
            "source": f"ERC-7562 Validation Scope Specification Rule [{rule_id}]",
            "role": role,
            "phase": phase,
            "topic": topic,
            "text": snippet,
        })

    # If section parsing is needed to catch remaining text
    if len(chunks) < 10:
        sections = re.split(r"\n(?=###?\s+)", raw_text)
        idx = 1
        for sec in sections:
            sec_clean = sec.strip()
            if not sec_clean or len(sec_clean) < 80:
                continue

            header_match = re.match(r"^###?\s+(.+)", sec_clean)
            header = header_match.group(1).strip() if header_match else "ERC-7562 Scope Section"
            rule_id_found = re.search(r"([A-Z]{2,4}-\d{3})", sec_clean)
            rid = rule_id_found.group(1) if rule_id_found else f"SCOPE-{idx:03d}"

            if rid not in seen_ids:
                seen_ids.add(rid)
                snippet = sec_clean.replace("\n", " ")
                if len(snippet) > 600:
                    snippet = snippet[:600] + "..."

                chunks.append({
                    "id": f"ERC7562-{rid}",
                    "rule_id": rid,
                    "source": f"ERC-7562 Specification: {header}",
                    "role": "generic",
                    "phase": "validation",
                    "topic": "validation scope",
                    "text": snippet,
                })
                idx += 1

    return chunks


def parse_audit_chunks(src_id: str, src_config: Dict[str, Any], raw_text: str) -> List[Dict[str, Any]]:
    """Parse finding-aware audit report chunks from fetched markdown/HTML content."""
    chunks = []
    text_clean = clean_html(raw_text) if "<html" in raw_text.lower() else raw_text

    sections = re.split(r"\n(?=###?\s+|\[[HMCL]-\d+\]|Vulnerability|Finding|Issue)", text_clean)
    idx = 1

    for sec in sections:
        sec_str = sec.strip()
        if len(sec_str) < 100:
            continue

        header_match = re.match(r"^(?:###?\s+)?(\[[^\]]+\][^\n]+|Finding[^\n]+|Vulnerability[^\n]+|Issue[^\n]+)", sec_str)
        header = header_match.group(1).strip() if header_match else f"Finding #{idx}"

        role = "account"
        phase = "validation"
        topic = "authorization"

        sec_lower = sec_str.lower()
        if "paymaster" in sec_lower or "coupon" in sec_lower or "sponsor" in sec_lower:
            role = "paymaster"
            topic = "sponsorship"
        elif "session" in sec_lower or "target" in sec_lower or "expiry" in sec_lower:
            role = "account"
            topic = "session key"
        elif "nonce" in sec_lower:
            topic = "nonce"
        elif "factory" in sec_lower or "create2" in sec_lower:
            role = "factory"
            phase = "deployment"
            topic = "factory initialization"
        elif "opcode" in sec_lower or "timestamp" in sec_lower or "storage" in sec_lower:
            role = "generic"
            topic = "validation scope"

        snippet = sec_str.replace("\n", " ")
        if len(snippet) > 600:
            snippet = snippet[:600] + "..."

        chunks.append({
            "id": f"AUDIT-{src_id.replace('SRC-', '')}-{idx:03d}",
            "source": f"{src_config['name']} - {header}",
            "role": role,
            "phase": phase,
            "topic": topic,
            "text": snippet,
        })
        idx += 1
        if idx > 15:
            break

    return chunks


def main():
    print("[*] Starting Corpus Rebuild & Real HTTP Fetch Pass...")
    fetched_data = {}

    for src in SOURCES_CONFIG:
        url = src["url"]
        print(f"[*] Fetching: {src['name']} ({url})")
        content, status, ts = fetch_url(url)

        if status != 200 and "alt_url" in src:
            print(f"    [-] Main URL returned status {status}. Trying alt URL: {src['alt_url']}")
            content, status, ts = fetch_url(src["alt_url"])

        raw_length = len(content)
        word_count = len(content.split())
        print(f"    [+] Status: {status} | Length: {raw_length} bytes | Words: {word_count}")

        fetched_data[src["id"]] = {
            "config": src,
            "raw_content": content,
            "status": status,
            "timestamp": ts,
            "raw_length": raw_length,
            "word_count": word_count,
        }

    print("\n[*] Processing Section-Aware Chunks from fetched content...")

    erc4337_chunks = []
    erc7562_chunks = []
    audit_chunks = []

    # 1. Parse ERC-4337
    erc4337_raw = fetched_data.get("SRC-ERC4337-SPEC", {}).get("raw_content", "")
    if erc4337_raw and "HTTPError" not in erc4337_raw:
        erc4337_chunks = parse_erc4337_chunks(erc4337_raw)
    fetched_data["SRC-ERC4337-SPEC"]["chunk_count"] = len(erc4337_chunks)

    # 2. Parse ERC-7562 (Preserving rule IDs)
    erc7562_raw = fetched_data.get("SRC-ERC7562-SPEC", {}).get("raw_content", "")
    if erc7562_raw and "HTTPError" not in erc7562_raw:
        erc7562_chunks = parse_erc7562_chunks(erc7562_raw)
    fetched_data["SRC-ERC7562-SPEC"]["chunk_count"] = len(erc7562_chunks)

    # 3. Parse Audits
    for src_id, data in fetched_data.items():
        if src_id in ["SRC-ERC4337-SPEC", "SRC-ERC7562-SPEC"]:
            continue
        raw = data.get("raw_content", "")
        chunks = parse_audit_chunks(src_id, data.get("config", {}), raw)
        data["chunk_count"] = len(chunks)
        audit_chunks.extend(chunks)

    # Write Manifest
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_sources": len(SOURCES_CONFIG),
        "total_chunks": len(erc4337_chunks) + len(erc7562_chunks) + len(audit_chunks),
        "sources": [
            {
                "source_id": src_id,
                "name": data["config"]["name"],
                "url": data["config"]["url"],
                "category": data["config"]["category"],
                "http_status": data["status"],
                "fetch_timestamp": data["timestamp"],
                "fetch_method": "urllib.request.urlopen (real HTTP GET)",
                "raw_bytes": data["raw_length"],
                "raw_words": data["word_count"],
                "chunks_derived": data.get("chunk_count", 0),
            }
            for src_id, data in fetched_data.items()
        ],
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    with open(ERC4337_PATH, "w", encoding="utf-8") as f:
        json.dump(erc4337_chunks, f, indent=2)

    with open(ERC7562_PATH, "w", encoding="utf-8") as f:
        json.dump(erc7562_chunks, f, indent=2)

    with open(AUDIT_PATH, "w", encoding="utf-8") as f:
        json.dump(audit_chunks, f, indent=2)

    print(f"\n[+] Manifest written to {MANIFEST_PATH}")
    print(f"[+] Total ERC-4337 Chunks: {len(erc4337_chunks)} -> {ERC4337_PATH}")
    print(f"[+] Total ERC-7562 Chunks: {len(erc7562_chunks)} -> {ERC7562_PATH}")
    print(f"[+] Total Audit Chunks: {len(audit_chunks)} -> {AUDIT_PATH}")
    print(f"[+] TOTAL CORPUS CHUNKS: {len(erc4337_chunks) + len(erc7562_chunks) + len(audit_chunks)}")


if __name__ == "__main__":
    main()
