#!/usr/bin/env python3
"""Score an opengrep JSON run against the OWASP Benchmark v1.2 expected results.

Two scores are produced:
  1. Category-matched precision/recall (official OWASP Benchmark style): a finding
     only counts for the CWE the test case actually targets.
  2. Raw finding volume: everything the tool emitted, which is what a customer
     actually has to triage.
"""
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Map socket-basics java rule ids -> OWASP Benchmark category
RULE_CATEGORY = {
    "java-sql-injection": "sqli",
    "java-jpa-sql-injection": "sqli",
    "java-command-injection": "cmdi",
    "java-path-traversal": "pathtraver",
    "java-ldap-injection": "ldapi",
    "java-insecure-random": "weakrand",
    "java-weak-crypto-md5": "hash",
    "java-weak-crypto-sha1": "hash",
    "java-weak-cipher": "crypto",
    "java-insecure-cookie": "securecookie",
    "java-xpath-injection": "xpathi",
    "java-trust-boundary-violation": "trustbound",
    "java-xss": "xss",
    "java-template-injection": "xss",
}

TEST_RE = re.compile(r"(BenchmarkTest\d{5})")


def load_expected(csv_path):
    expected = {}
    with open(csv_path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            expected[name] = {"category": category, "real": real.lower() == "true", "cwe": cwe}
    return expected


def main(results_json, expected_csv):
    expected = load_expected(expected_csv)
    data = json.loads(Path(results_json).read_text())
    findings = data.get("results", [])

    # Deduplicate: one (test case, rule) pair counts once, matching how a
    # reviewer triages "does this tool flag this file for this issue".
    hits = set()
    per_rule_total = defaultdict(int)
    off_benchmark = 0

    for f in findings:
        rule = f.get("check_id", "").split(".")[-1]
        per_rule_total[rule] += 1
        m = TEST_RE.search(f.get("path", ""))
        if not m:
            off_benchmark += 1
            continue
        hits.add((m.group(1), rule))

    # Category-matched scoring
    cat_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0})

    flagged = defaultdict(set)  # test -> {categories flagged}
    for test, rule in hits:
        cat = RULE_CATEGORY.get(rule)
        if cat is None:
            continue
        flagged[test].add(cat)
        exp = expected.get(test)
        if not exp or exp["category"] != cat:
            continue
        if exp["real"]:
            rule_stats[rule]["tp"] += 1
        else:
            rule_stats[rule]["fp"] += 1

    scored_cats = set(RULE_CATEGORY.values())
    for test, exp in expected.items():
        cat = exp["category"]
        if cat not in scored_cats:
            continue
        did_flag = cat in flagged.get(test, set())
        s = cat_stats[cat]
        if exp["real"] and did_flag:
            s["tp"] += 1
        elif exp["real"] and not did_flag:
            s["fn"] += 1
        elif not exp["real"] and did_flag:
            s["fp"] += 1
        else:
            s["tn"] += 1

    def pct(n, d):
        return f"{100.0 * n / d:5.1f}%" if d else "    -"

    print(f"\n=== {Path(results_json).name} ===")
    print(f"Total raw findings emitted: {len(findings)}")
    print(f"Unique (testcase, rule) pairs: {len(hits)}")
    print(f"Findings outside benchmark test files: {off_benchmark}\n")

    print("--- Per-category (OWASP Benchmark scoring: CWE-matched) ---")
    print(f"{'category':14} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} {'prec':>7} {'recall':>7} {'FP rate':>8} {'score':>7}")
    tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for cat in sorted(cat_stats):
        s = cat_stats[cat]
        for k in tot:
            tot[k] += s[k]
        tpr = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0
        fpr = s["fp"] / (s["fp"] + s["tn"]) if (s["fp"] + s["tn"]) else 0
        print(f"{cat:14} {s['tp']:5} {s['fp']:5} {s['fn']:5} {s['tn']:5} "
              f"{pct(s['tp'], s['tp'] + s['fp'])} {pct(s['tp'], s['tp'] + s['fn'])} "
              f"{pct(s['fp'], s['fp'] + s['tn'])} {100 * (tpr - fpr):6.1f}")
    tpr = tot["tp"] / (tot["tp"] + tot["fn"]) if (tot["tp"] + tot["fn"]) else 0
    fpr = tot["fp"] / (tot["fp"] + tot["tn"]) if (tot["fp"] + tot["tn"]) else 0
    print(f"{'TOTAL':14} {tot['tp']:5} {tot['fp']:5} {tot['fn']:5} {tot['tn']:5} "
          f"{pct(tot['tp'], tot['tp'] + tot['fp'])} {pct(tot['tp'], tot['tp'] + tot['fn'])} "
          f"{pct(tot['fp'], tot['fp'] + tot['tn'])} {100 * (tpr - fpr):6.1f}")

    print("\n--- Per-rule (CWE-matched TP/FP) ---")
    print(f"{'rule':38} {'TP':>5} {'FP':>5} {'prec':>7} {'raw findings':>13}")
    for rule in sorted(per_rule_total, key=lambda r: -per_rule_total[r]):
        s = rule_stats.get(rule, {"tp": 0, "fp": 0})
        print(f"{rule:38} {s['tp']:5} {s['fp']:5} {pct(s['tp'], s['tp'] + s['fp'])} {per_rule_total[rule]:13}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
