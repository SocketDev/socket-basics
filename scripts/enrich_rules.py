#!/usr/bin/env python3
"""
Phase 2: Enrich SAST rules with missing metadata fields.

This script adds the following metadata fields to rules in socket_basics/rules/:
  - subcategory (derived from CWE)
  - vulnerability_class (derived from subcategory)
  - owasp (derived from CWE)
  - references (for framework-specific rules)

It uses a string-based approach to insert lines into metadata blocks without
reformatting the entire YAML file, preserving comments and formatting.

Usage:
    python scripts/enrich_rules.py
"""

import os
import re
import sys
import yaml

# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

CWE_TO_SUBCATEGORY = {
    # injection
    "CWE-78": "injection", "CWE-79": "xss", "CWE-89": "injection",
    "CWE-90": "injection", "CWE-91": "injection", "CWE-94": "injection",
    "CWE-95": "injection", "CWE-98": "injection", "CWE-74": "injection",
    "CWE-88": "injection", "CWE-134": "injection", "CWE-943": "injection",
    "CWE-915": "injection", "CWE-1321": "injection", "CWE-1336": "injection",
    "CWE-470": "injection", "CWE-611": "injection", "CWE-117": "injection",
    # crypto
    "CWE-208": "crypto", "CWE-295": "crypto", "CWE-310": "crypto",
    "CWE-319": "crypto", "CWE-322": "crypto", "CWE-326": "crypto",
    "CWE-327": "crypto", "CWE-330": "crypto", "CWE-338": "crypto",
    "CWE-347": "crypto",
    # authentication
    "CWE-259": "authentication", "CWE-287": "authentication",
    "CWE-384": "authentication", "CWE-521": "authentication",
    "CWE-798": "authentication", "CWE-916": "authentication",
    # access-control
    "CWE-22": "access-control", "CWE-73": "access-control",
    "CWE-601": "access-control", "CWE-639": "access-control",
    "CWE-862": "access-control", "CWE-863": "access-control",
    "CWE-915": "access-control",  # mass assignment could go here too
    # configuration
    "CWE-16": "configuration", "CWE-200": "configuration",
    "CWE-209": "configuration", "CWE-250": "configuration",
    "CWE-276": "configuration", "CWE-489": "configuration",
    "CWE-614": "configuration", "CWE-693": "configuration",
    "CWE-732": "configuration", "CWE-926": "configuration",
    "CWE-942": "configuration", "CWE-477": "configuration",
    "CWE-1104": "configuration", "CWE-1059": "configuration",
    # integrity
    "CWE-345": "integrity", "CWE-353": "integrity",
    "CWE-494": "integrity", "CWE-502": "integrity",
    # logging
    "CWE-532": "logging", "CWE-778": "logging",
    # error-handling
    "CWE-248": "error-handling", "CWE-396": "error-handling",
    "CWE-703": "error-handling", "CWE-755": "error-handling",
    # design
    "CWE-20": "design", "CWE-307": "design", "CWE-362": "design",
    "CWE-367": "design", "CWE-667": "design", "CWE-697": "design",
    "CWE-704": "design",
    # dos
    "CWE-400": "dos", "CWE-409": "dos", "CWE-1333": "dos",
    # file-operations
    "CWE-377": "file-operations",
    # upload
    "CWE-434": "upload",
    # ssrf
    "CWE-918": "ssrf",
    # deprecated (memory safety for C/C++)
    "CWE-119": "deprecated", "CWE-120": "deprecated", "CWE-131": "deprecated",
    "CWE-190": "deprecated", "CWE-242": "deprecated", "CWE-401": "deprecated",
    "CWE-415": "deprecated", "CWE-416": "deprecated", "CWE-476": "deprecated",
    "CWE-479": "deprecated",
    # misc
    "CWE-312": "crypto", "CWE-522": "crypto",
    "CWE-352": "access-control",
}

SUBCATEGORY_TO_VULN_CLASS = {
    "injection": "Injection Vulnerability",
    "xss": "Cross-Site Scripting (XSS)",
    "crypto": "Cryptographic Weakness",
    "authentication": "Authentication Weakness",
    "access-control": "Access Control Violation",
    "configuration": "Security Misconfiguration",
    "integrity": "Insecure Deserialization",
    "logging": "Sensitive Data Exposure",
    "error-handling": "Improper Error Handling",
    "design": "Insecure Design",
    "dos": "Denial of Service",
    "file-operations": "Insecure File Operation",
    "upload": "Unrestricted File Upload",
    "ssrf": "Server-Side Request Forgery",
    "deprecated": "Memory Safety Violation",
    "async": "Improper Error Handling",
    "process": "Injection Vulnerability",
    "proxy": "Security Misconfiguration",
    "type-safety": "Insecure Design",
    "performance": "Other",
}

CWE_TO_OWASP = {
    # A01:2021 — Broken Access Control
    **{f"CWE-{n}": "A01:2021" for n in [22, 23, 35, 59, 200, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275]},
    # A02:2021 — Cryptographic Failures
    **{f"CWE-{n}": "A02:2021" for n in [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 798, 916]},
    # A03:2021 — Injection
    **{f"CWE-{n}": "A03:2021" for n in [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 117, 134, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 943, 1236, 1321, 1336]},
    # A04:2021 — Insecure Design
    **{f"CWE-{n}": "A04:2021" for n in [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173]},
    # A05:2021 — Security Misconfiguration
    **{f"CWE-{n}": "A05:2021" for n in [2, 11, 13, 15, 16, 260, 315, 489, 497, 520, 526, 537, 541, 547, 611, 614, 693, 732, 756, 776, 942, 1004, 1032, 1174]},
    # A06:2021 — Vulnerable and Outdated Components
    **{f"CWE-{n}": "A06:2021" for n in [477, 1104, 1059]},
    # A07:2021 — Auth Failures
    **{f"CWE-{n}": "A07:2021" for n in [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216]},
    # A08:2021 — Data Integrity Failures
    **{f"CWE-{n}": "A08:2021" for n in [345, 353, 426, 494, 502, 565, 784, 829, 830, 915]},
    # A09:2021 — Logging Failures
    **{f"CWE-{n}": "A09:2021" for n in [117, 223, 532, 778]},
    # A10:2021 — SSRF
    **{f"CWE-{n}": "A10:2021" for n in [918]},
}

FRAMEWORK_REFS = {
    "phoenix": ["https://hexdocs.pm/phoenix/security.html"],
    "play": ["https://www.playframework.com/documentation/latest/SecurityHeaders"],
    "rails": ["https://guides.rubyonrails.org/security.html"],
    "aspnet": ["https://learn.microsoft.com/en-us/aspnet/core/security/"],
    "aspnetcore": ["https://learn.microsoft.com/en-us/aspnet/core/security/"],
    "express": ["https://expressjs.com/en/advanced/best-practice-security.html"],
    "react": ["https://react.dev/reference/react-dom/components/common"],
    "spring": ["https://docs.spring.io/spring-security/reference/"],
    "django": ["https://docs.djangoproject.com/en/stable/topics/security/"],
    "flask": ["https://flask.palletsprojects.com/en/stable/security/"],
    "laravel": ["https://laravel.com/docs/master/security"],
    "symfony": ["https://symfony.com/doc/current/security.html"],
    "wordpress": ["https://developer.wordpress.org/advanced-administration/security/"],
    "nextjs": ["https://nextjs.org/docs/app/building-your-application/authentication"],
    "otp": ["https://www.erlang.org/doc/design_principles/"],
    "cowboy": ["https://ninenines.eu/docs/en/cowboy/"],
    "coredata": ["https://developer.apple.com/documentation/coredata"],
    "swiftui": ["https://developer.apple.com/documentation/swiftui"],
    "rocket": ["https://rocket.rs/guide/"],
    "tokio": ["https://tokio.rs/tokio/tutorial"],
    "actix": ["https://actix.rs/docs/"],
    "warp": ["https://docs.rs/warp/"],
    "diesel": ["https://diesel.rs/guides/"],
}


def parse_metadata_from_yaml(filepath):
    """Parse YAML file and return list of rule metadata dicts with rule IDs."""
    with open(filepath) as f:
        data = yaml.safe_load(f)
    rules = []
    for rule in data.get("rules", []):
        meta = rule.get("metadata", {})
        rules.append({
            "id": rule.get("id", ""),
            "metadata": meta,
        })
    return rules


def find_metadata_blocks(content):
    """
    Find all metadata blocks in the YAML content.

    Returns a list of (start, end, indent, fields_dict) tuples where:
    - start: byte offset of 'metadata:' line
    - end: byte offset of the end of the metadata block
    - indent: the indentation string of the metadata key (e.g., '    ')
    - fields_dict: dict of field_name -> True for existing fields
    """
    blocks = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match a metadata: line (must be at proper indentation level)
        m = re.match(r"^(\s+)metadata:\s*$", line)
        if m:
            meta_indent = m.group(1)
            field_indent = meta_indent + "  "
            start_line = i
            fields = {}
            j = i + 1
            # Collect all fields in this metadata block
            while j < len(lines):
                fline = lines[j]
                # Empty line or comment at field indent level -- keep going
                if fline.strip() == "" or fline.strip().startswith("#"):
                    # Check if next non-empty line is still in the metadata block
                    # An empty line signals end of rule in most YAML files
                    # But we need to handle references list items
                    if fline.strip() == "":
                        # End of metadata block
                        break
                    j += 1
                    continue
                # Check if this line is a field in the metadata block
                fm = re.match(r"^" + re.escape(field_indent) + r"(\w[\w_-]*):", fline)
                if fm:
                    fields[fm.group(1)] = True
                    j += 1
                    # If this is a list field (like references), skip list items
                    while j < len(lines):
                        list_line = lines[j]
                        if re.match(r"^" + re.escape(field_indent) + r"  - ", list_line):
                            j += 1
                        else:
                            break
                    continue
                else:
                    # Line doesn't match field pattern -- end of metadata block
                    break
            blocks.append((start_line, j, meta_indent, fields))
            i = j
        else:
            i += 1
    return blocks


def enrich_file(filepath, stats):
    """Enrich a single YAML file with missing metadata fields."""
    with open(filepath) as f:
        content = f.read()

    # Parse with PyYAML to get structured metadata
    rules_meta = parse_metadata_from_yaml(filepath)

    # Find metadata blocks in the raw text
    blocks = find_metadata_blocks(content)

    if len(blocks) != len(rules_meta):
        print(f"WARNING: {filepath}: found {len(blocks)} metadata blocks but "
              f"{len(rules_meta)} rules. Skipping file.")
        return content

    lines = content.split("\n")
    insertions = []  # (line_number, lines_to_insert)

    for idx, (start_line, end_line, meta_indent, existing_fields) in enumerate(blocks):
        rule = rules_meta[idx]
        meta = rule["metadata"]
        rule_id = rule["id"]
        field_indent = meta_indent + "  "
        new_lines = []

        cwe = str(meta.get("cwe", ""))
        existing_subcategory = meta.get("subcategory")
        existing_owasp = meta.get("owasp")
        existing_vuln_class = meta.get("vulnerability_class")
        existing_references = meta.get("references")
        existing_framework = meta.get("framework")

        # 1. Add subcategory if missing
        subcategory = existing_subcategory
        if "subcategory" not in existing_fields and cwe in CWE_TO_SUBCATEGORY:
            subcategory = CWE_TO_SUBCATEGORY[cwe]
            new_lines.append(f"{field_indent}subcategory: {subcategory}")
            stats["subcategory_added"] += 1

        # 2. Add vulnerability_class if missing
        if "vulnerability_class" not in existing_fields:
            # Use the subcategory (existing or just computed) to look up vuln class
            sc = subcategory or existing_subcategory
            if sc and sc in SUBCATEGORY_TO_VULN_CLASS:
                vc = SUBCATEGORY_TO_VULN_CLASS[sc]
                new_lines.append(f"{field_indent}vulnerability_class: \"{vc}\"")
                stats["vulnerability_class_added"] += 1

        # 3. Add owasp if missing
        if "owasp" not in existing_fields and cwe in CWE_TO_OWASP:
            owasp = CWE_TO_OWASP[cwe]
            new_lines.append(f"{field_indent}owasp: \"{owasp}\"")
            stats["owasp_added"] += 1

        # 4. Add references for framework rules if missing
        if ("references" not in existing_fields and existing_framework
                and str(existing_framework) in FRAMEWORK_REFS):
            refs = FRAMEWORK_REFS[str(existing_framework)]
            new_lines.append(f"{field_indent}references:")
            for ref in refs:
                new_lines.append(f"{field_indent}  - {ref}")
            stats["references_added"] += 1

        if new_lines:
            # Insert new lines just before the end of the metadata block
            # (i.e., right before the blank line or next rule)
            insertions.append((end_line, new_lines))

    if not insertions:
        return content

    # Apply insertions in reverse order to preserve line numbers
    for insert_line, new_lines in reversed(insertions):
        lines[insert_line:insert_line] = new_lines

    return "\n".join(lines)


def main():
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "socket_basics", "rules")

    if not os.path.isdir(rules_dir):
        print(f"ERROR: Rules directory not found: {rules_dir}")
        sys.exit(1)

    stats = {
        "subcategory_added": 0,
        "vulnerability_class_added": 0,
        "owasp_added": 0,
        "references_added": 0,
        "files_processed": 0,
        "rules_processed": 0,
    }

    yml_files = sorted(f for f in os.listdir(rules_dir) if f.endswith(".yml"))
    print(f"Found {len(yml_files)} YAML files in {rules_dir}")

    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        rules_meta = parse_metadata_from_yaml(filepath)
        stats["rules_processed"] += len(rules_meta)

        enriched = enrich_file(filepath, stats)
        with open(filepath, "w") as f:
            f.write(enriched)
        stats["files_processed"] += 1
        print(f"  Processed {fname} ({len(rules_meta)} rules)")

    print(f"\n{'='*60}")
    print(f"Enrichment complete!")
    print(f"{'='*60}")
    print(f"Files processed:          {stats['files_processed']}")
    print(f"Rules processed:          {stats['rules_processed']}")
    print(f"subcategory added:        {stats['subcategory_added']}")
    print(f"vulnerability_class added:{stats['vulnerability_class_added']}")
    print(f"owasp added:              {stats['owasp_added']}")
    print(f"references added:         {stats['references_added']}")

    # Verify all files still parse
    print(f"\nVerifying YAML syntax...")
    errors = 0
    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                print(f"  WARNING: {fname} has no 'rules' key")
                errors += 1
        except yaml.YAMLError as e:
            print(f"  ERROR: {fname} failed to parse: {e}")
            errors += 1

    if errors:
        print(f"\n{errors} file(s) had issues!")
        sys.exit(1)
    else:
        print(f"All {len(yml_files)} files parse successfully.")

    # Count final field coverage
    print(f"\nFinal field coverage:")
    total_rules = 0
    field_counts = {
        "subcategory": 0,
        "vulnerability_class": 0,
        "owasp": 0,
        "references": 0,
    }
    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        with open(filepath) as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            total_rules += 1
            meta = rule.get("metadata", {})
            for field in field_counts:
                if field in meta:
                    field_counts[field] += 1

    print(f"  Total rules: {total_rules}")
    for field, count in field_counts.items():
        print(f"  {field}: {count}/{total_rules} ({count*100//total_rules}%)")


if __name__ == "__main__":
    main()
