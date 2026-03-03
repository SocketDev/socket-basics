#!/usr/bin/env python3
"""Fetch the MITRE CWE catalog and generate a Python lookup table.

Downloads the full CWE catalog from MITRE, parses it, and generates
a Python dict at socket_basics/core/connector/opengrep/cwe_catalog.py.

Usage:
    python scripts/update_cwe_catalog.py

Re-run anytime MITRE publishes new CWE entries to update the local table.
"""

import csv
import io
import re
import sys
import textwrap
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = (
    PROJECT_ROOT
    / "socket_basics"
    / "core"
    / "connector"
    / "opengrep"
    / "cwe_catalog.py"
)

# MITRE CWE Research Concepts view — covers all software weaknesses
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) reverse mapping: CWE-ID -> OWASP category
# Source: https://owasp.org/Top10/
# ---------------------------------------------------------------------------
_OWASP_MAPPING: dict[str, str] = {}

# A01:2021 — Broken Access Control
for _id in [
    22, 23, 35, 59, 200, 219, 264, 275, 276, 284, 285, 352, 359, 377,
    402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668,
    706, 862, 863, 913, 922, 1275,
]:
    _OWASP_MAPPING[f"CWE-{_id}"] = "A01:2021"

# A02:2021 — Cryptographic Failures
for _id in [
    261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329,
    330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760,
    780, 798, 916,
]:
    _OWASP_MAPPING[f"CWE-{_id}"] = "A02:2021"

# A03:2021 — Injection
for _id in [
    20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95,
    96, 97, 98, 99, 100, 113, 116, 117, 134, 138, 184, 470, 471, 564,
    610, 643, 644, 652, 917, 943, 1236, 1321, 1336,
]:
    _OWASP_MAPPING[f"CWE-{_id}"] = "A03:2021"

# A04:2021 — Insecure Design
for _id in [
    73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313,
    316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598,
    602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021,
    1173,
]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A04:2021")

# A05:2021 — Security Misconfiguration
for _id in [
    2, 11, 13, 15, 16, 260, 315, 489, 497, 520, 526, 537, 541, 547,
    611, 614, 693, 732, 756, 776, 942, 1004, 1032, 1174,
]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A05:2021")

# A06:2021 — Vulnerable and Outdated Components
for _id in [477, 1104, 1059]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A06:2021")

# A07:2021 — Identification and Authentication Failures
for _id in [
    255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307,
    346, 384, 521, 613, 620, 640, 798, 940, 1216,
]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A07:2021")

# A08:2021 — Software and Data Integrity Failures
for _id in [345, 353, 426, 494, 502, 565, 784, 829, 830, 915]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A08:2021")

# A09:2021 — Security Logging and Monitoring Failures
for _id in [117, 223, 532, 778]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A09:2021")

# A10:2021 — Server-Side Request Forgery
for _id in [918]:
    _OWASP_MAPPING.setdefault(f"CWE-{_id}", "A10:2021")


# ---------------------------------------------------------------------------
# Vulnerability category classification
# ---------------------------------------------------------------------------

# Explicit overrides for CWEs where keyword matching would be wrong
_CATEGORY_OVERRIDES: dict[str, str] = {
    # XSS variants
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-80": "Cross-Site Scripting (XSS)",
    "CWE-83": "Cross-Site Scripting (XSS)",
    "CWE-87": "Cross-Site Scripting (XSS)",
    # Specific vulnerability classes
    "CWE-502": "Insecure Deserialization",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-1321": "Prototype Pollution",
    "CWE-1336": "Template Injection",
    "CWE-470": "Unsafe Reflection",
    # CWEs used in our rules that keyword matching misses
    "CWE-16": "Security Misconfiguration",
    "CWE-98": "Injection Vulnerability",
    "CWE-117": "Sensitive Data Exposure",
    "CWE-131": "Memory Safety Violation",
    "CWE-208": "Cryptographic Weakness",
    "CWE-242": "Memory Safety Violation",
    "CWE-310": "Cryptographic Weakness",
    "CWE-330": "Cryptographic Weakness",
    "CWE-345": "Insecure Deserialization",
    "CWE-353": "Insecure Deserialization",
    "CWE-477": "Security Misconfiguration",
    "CWE-479": "Memory Safety Violation",
    "CWE-494": "Insecure Deserialization",
    "CWE-667": "Insecure Design",
    "CWE-693": "Security Misconfiguration",
    "CWE-697": "Insecure Design",
    "CWE-704": "Insecure Design",
    "CWE-915": "Injection Vulnerability",
    "CWE-926": "Security Misconfiguration",
    "CWE-942": "Security Misconfiguration",
    "CWE-943": "Injection Vulnerability",
    "CWE-1059": "Security Misconfiguration",
    "CWE-1104": "Security Misconfiguration",
}

# Ordered keyword rules — first match wins
_CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("Injection Vulnerability", [
        "sql injection", "os command", "command injection", "code injection",
        "eval injection", "ldap injection", "xpath injection", "injection",
        "nosql", "format string", "argument delimiter",
    ]),
    ("Cross-Site Scripting (XSS)", [
        "cross-site scripting", "xss",
    ]),
    ("Cryptographic Weakness", [
        "cryptograph", "cipher", "hash", "random number", "prng", "rng",
        "certificate", "tls", "ssl", "encrypt", "key exchange", "key manage",
        "cleartext transmission", "password hash",
    ]),
    ("Authentication Weakness", [
        "authenticat", "credential", "password", "session fixation", "brute force",
        "login", "hard-coded password",
    ]),
    ("Access Control Violation", [
        "access control", "authorization", "traversal", "path traversal",
        "redirect", "permission", "privilege", "idor", "direct object",
    ]),
    ("Memory Safety Violation", [
        "buffer overflow", "buffer over-read", "buffer underwrite", "buffer copy",
        "heap-based", "stack-based", "out-of-bounds", "use after free",
        "double free", "null pointer", "integer overflow", "integer underflow",
        "memory", "free of pointer", "uninitialized",
    ]),
    ("Security Misconfiguration", [
        "misconfigur", "debug", "default", "configuration", "verbose error",
        "information exposure", "information leak", "error message",
        "sensitive cookie", "cors",
    ]),
    ("Insecure Deserialization", [
        "deserializ", "pickle", "unmarshall", "untrusted data",
    ]),
    ("Denial of Service", [
        "denial of service", "resource consumption", "regular expression",
        "redos", "decompression bomb", "amplification", "loop",
    ]),
    ("Sensitive Data Exposure", [
        "sensitive information", "log file", "cleartext storage", "plaintext",
        "insufficient logging",
    ]),
    ("Insecure File Operation", [
        "temporary file", "file name", "file path", "symlink", "race condition",
    ]),
    ("Improper Error Handling", [
        "exception", "error handling", "exceptional condition",
    ]),
    ("Insecure Design", [
        "input validation", "improper validation", "missing validation",
    ]),
    ("Server-Side Request Forgery (SSRF)", [
        "server-side request forgery", "ssrf",
    ]),
]


def _classify_cwe(cwe_id: str, name: str) -> str:
    """Map a CWE to a vulnerability category using overrides + keyword matching."""
    if cwe_id in _CATEGORY_OVERRIDES:
        return _CATEGORY_OVERRIDES[cwe_id]
    name_lower = name.lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in name_lower for kw in keywords):
            return category
    return "Other"


def _clean_description(desc: str) -> str:
    """Normalize whitespace and truncate excessively long descriptions."""
    desc = re.sub(r"\s+", " ", desc).strip()
    # Truncate to ~250 chars at a sentence boundary for readability
    if len(desc) > 300:
        # Try to cut at a period
        cut = desc[:300].rfind(". ")
        if cut > 100:
            desc = desc[: cut + 1]
        else:
            desc = desc[:297] + "..."
    return desc


def fetch_cwe_csv() -> list[dict]:
    """Download and parse the MITRE CWE CSV catalog."""
    print(f"Downloading CWE catalog from {CWE_CSV_URL} ...")
    req = urllib.request.Request(CWE_CSV_URL, headers={"User-Agent": "socket-basics/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        zip_data = resp.read()

    print(f"Downloaded {len(zip_data)} bytes, extracting ...")
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
        if not csv_names:
            raise RuntimeError(f"No CSV found in ZIP. Contents: {zf.namelist()}")
        csv_data = zf.read(csv_names[0]).decode("utf-8-sig")

    reader = csv.DictReader(io.StringIO(csv_data))
    entries = []
    for row in reader:
        cwe_num = row.get("CWE-ID", "").strip()
        name = row.get("Name", "").strip()
        description = row.get("Description", "").strip()
        status = row.get("Status", "").strip()

        if not cwe_num or not name:
            continue
        # Skip deprecated/obsolete entries
        if status.lower() in ("deprecated", "obsolete"):
            continue

        cwe_id = f"CWE-{cwe_num}"
        entries.append(
            {
                "id": cwe_id,
                "name": name,
                "description": _clean_description(description),
                "category": _classify_cwe(cwe_id, name),
                "owasp": _OWASP_MAPPING.get(cwe_id, ""),
            }
        )

    # Add synthetic entries for deprecated/pillar CWEs that our rules still use
    # but MITRE removed from the Research Concepts view.
    seen = {e["id"] for e in entries}
    for cwe_id, info in _SYNTHETIC_ENTRIES.items():
        if cwe_id not in seen:
            entries.append(
                {
                    "id": cwe_id,
                    "name": info["name"],
                    "description": info["description"],
                    "category": _classify_cwe(cwe_id, info["name"]),
                    "owasp": _OWASP_MAPPING.get(cwe_id, ""),
                }
            )

    return entries


# Deprecated/pillar CWEs still referenced by our rule YAML files.
# These are absent from the Research Concepts CSV but needed in the catalog.
_SYNTHETIC_ENTRIES: dict[str, dict[str, str]] = {
    "CWE-16": {
        "name": "Configuration",
        "description": (
            "The application uses an insecure or incorrect configuration "
            "setting, which may weaken its overall security posture."
        ),
    },
    "CWE-310": {
        "name": "Cryptographic Issues",
        "description": (
            "The application contains a general cryptographic weakness, "
            "such as misuse of primitives or improper key management, "
            "that may undermine data protection."
        ),
    },
}


def generate_python(entries: list[dict]) -> str:
    """Generate the cwe_catalog.py source code."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        '"""CWE Catalog — auto-generated lookup table.',
        "",
        f"Source: MITRE CWE Research Concepts (View 1000)",
        f"URL: {CWE_CSV_URL}",
        f"Generated: {now}",
        f"Entries: {len(entries)}",
        "",
        "Run `python scripts/update_cwe_catalog.py` to regenerate.",
        '"""',
        "",
        "",
        "CWE_CATALOG: dict[str, dict[str, str]] = {",
    ]

    for e in sorted(entries, key=lambda x: int(x["id"].split("-")[1])):
        cwe_id = e["id"]
        name = e["name"].replace('"', '\\"')
        desc = e["description"].replace('"', '\\"')
        cat = e["category"].replace('"', '\\"')
        owasp = e["owasp"]

        lines.append(f'    "{cwe_id}": {{')
        lines.append(f'        "name": "{name}",')
        lines.append(f'        "description": "{desc}",')
        lines.append(f'        "category": "{cat}",')
        if owasp:
            lines.append(f'        "owasp": "{owasp}",')
        lines.append("    },")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    entries = fetch_cwe_csv()
    print(f"Parsed {len(entries)} CWE entries")

    # Stats
    categories = {}
    for e in entries:
        cat = e["category"]
        categories[cat] = categories.get(cat, 0) + 1
    print("\nCategory distribution:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    owasp_count = sum(1 for e in entries if e["owasp"])
    print(f"\nOWASP mapped: {owasp_count}/{len(entries)}")

    source = generate_python(entries)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(source, encoding="utf-8")
    print(f"\nWrote {OUTPUT_FILE} ({len(source)} bytes, {len(entries)} entries)")


if __name__ == "__main__":
    main()
