# Alert Quality Improvement Plan

**Status:** Draft
**Date:** 2026-02-05
**Branch:** hackathon
**Prerequisite:** Alert enrichment quick wins (commit `cfcee2f`) — CWE/OWASP extraction, auto-generated references, and `detailedReport` markdown are already in place.

---

## Problem Statement

Customers see alerts with descriptions like *"Generic ad-hoc alert, uploaded by user or produced by system diagnostics"* and a raw rule ID like `python-sql-injection` as the title. This happens because:

1. **Alert `type` is always `'generic'`** — the Socket Dashboard renders a generic fallback when it doesn't recognize the alert type
2. **Rule messages are sparse** — ~60% of our 499 rules have terse one-liner messages with no remediation context
3. **No human-readable vulnerability name** — customers see `python-sql-injection`, not "SQL Injection"
4. **Missing metadata** — `vulnerability_class`, `likelihood`, `impact`, OWASP (81% of rules lack it), `references` (99.8% lack it), and `fix` (99.6% lack it) are absent from rule definitions

The enrichment work in `cfcee2f` extracts everything the rules *already provide*, but the rules themselves need to provide more.

---

## Phase Overview

| Phase | Scope | Effort | Files Changed | Impact |
|-------|-------|--------|---------------|--------|
| **1** | CWE lookup table + connector improvements | Small | 1-2 files | Alerts with a CWE (498/499) get a human-readable title and description |
| **2** | Rule metadata enrichment (all 499 rules) | Medium | 15 YAML files | OWASP, references, vulnerability_class on every alert |
| **3** | Rule message rewrite | Large | 15 YAML files | Every alert explains What/Why/How |
| **4** | Dataflow traces + advanced enrichment | Medium | 1-2 files | Taint-mode alerts show source-to-sink flow |

---

## Phase 1: CWE Lookup Table + Connector Improvements

**Goal:** Every alert with a CWE (498 of 499 rules) gets a human-readable vulnerability name and description, sourced from a CWE lookup table, with zero rule file changes. The one rule without a CWE (`js-react-missing-key`) will fall back to the raw rule message.

**Files to change:**
- `socket_basics/core/connector/opengrep/__init__.py` (alert construction block)
- New: `socket_basics/core/connector/opengrep/cwe_catalog.py` (lookup table)

### 1.1 Create CWE Catalog Lookup Table

A Python dict mapping CWE IDs to human-readable names and descriptions. 498 of our 499 rules reference one of 90 unique CWEs. The top 20 CWEs by rule count cover 68% of rules (339/498):

```python
CWE_CATALOG = {
    "CWE-327": {
        "name": "Broken or Risky Cryptographic Algorithm",
        "description": "The code uses a cryptographic algorithm that is known to be weak or insufficient. This may allow attackers to decrypt sensitive data or bypass integrity checks.",
        "category": "Cryptographic Weakness",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "User-supplied input is included in a SQL query without proper sanitization, potentially allowing attackers to read, modify, or delete database contents.",
        "category": "Injection Vulnerability",
    },
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "description": "Credentials such as passwords, API keys, or cryptographic keys are embedded directly in source code, making them easily discoverable if the code is exposed.",
        "category": "Authentication Weakness",
    },
    # ... remaining 87 CWEs ...
}
```

Full catalog of all 90 CWEs is provided in [Appendix A](#appendix-a-cwe-catalog).

### 1.2 Use CWE Catalog in Alert Construction

In the alert construction block (after the existing enrichment code), add:

```python
from .cwe_catalog import CWE_CATALOG

# After extracting _cwe from metadata:
_cwe_info = CWE_CATALOG.get(_cwe, {})

# Add human-readable fields to props
if _cwe_info:
    alert['props']['vulnerabilityName'] = _cwe_info.get('name', '')
    alert['props']['vulnerabilityCategory'] = _cwe_info.get('category', '')
    # Use CWE description as fallback when rule message is sparse
    if len(message) < 60:  # sparse message threshold
        alert['props']['enrichedDescription'] = _cwe_info.get('description', '')
```

### 1.3 Extract Additional Metadata Fields

Extract fields that some rules already provide but the connector currently ignores:

```python
# Already extracted: cwe, owasp, subcategory, fix, references, confidence
# Add these:
_vulnerability_class = _metadata.get('vulnerability_class', '')
_likelihood = _metadata.get('likelihood', '')
_impact = _metadata.get('impact', '')
_technology = _metadata.get('technology', '')
_framework = _metadata.get('framework', '')

if _vulnerability_class:
    alert['props']['vulnerabilityClass'] = _vulnerability_class
if _likelihood:
    alert['props']['likelihood'] = _likelihood
if _impact:
    alert['props']['impact'] = _impact
if _technology:
    alert['props']['technology'] = _technology
if _framework:
    alert['props']['framework'] = _framework
```

### 1.4 Improve `detailedReport` Markdown

Incorporate CWE catalog data into the markdown report:

```markdown
## SQL Injection

**Description:** SQL injection vulnerability detected. User-controlled data flows into
SQL query without proper sanitization. Use parameterized queries with placeholders
(?, %s) to prevent SQL injection.

**Location:** `app/models/user.py` (line 42)

```python
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

**Severity:** critical | **Confidence:** high

**What is CWE-89?** User-supplied input is included in a SQL query without proper
sanitization, potentially allowing attackers to read, modify, or delete database contents.

**References:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [OWASP Top 10 A03:2021](https://owasp.org/Top10/A03/)
```

The "What is CWE-X?" section is pulled from the CWE catalog and provides context even when the rule message is sparse.

### 1.5 Acceptance Criteria

- [ ] Every alert with a CWE has `vulnerabilityName` in props (e.g., "SQL Injection")
- [ ] Every alert with a CWE has `vulnerabilityCategory` in props (e.g., "Injection Vulnerability")
- [ ] Sparse messages (< 60 chars) get `enrichedDescription` from CWE catalog
- [ ] `detailedReport` includes CWE explainer section
- [ ] All 90 CWEs in our rules are covered in the catalog
- [ ] No changes to rule YAML files

---

## Phase 2: Rule Metadata Enrichment

**Goal:** Add `vulnerability_class`, OWASP mappings, and `references` to all 499 rules across 15 YAML files.

**Files to change:** All files in `socket_basics/rules/*.yml`

### 2.1 Add `vulnerability_class` to All Rules

Map each rule to one of 20 standardized vulnerability class names derived from the existing `subcategory` values and CWE associations:

| vulnerability_class | Maps From subcategory | Associated CWEs |
|---|---|---|
| Injection Vulnerability | `injection`, `process` | CWE-78, CWE-89, CWE-90, CWE-94, CWE-95, CWE-943 |
| Cross-Site Scripting (XSS) | `xss` | CWE-79 |
| Cryptographic Weakness | `crypto` | CWE-208, CWE-295, CWE-310, CWE-319, CWE-326, CWE-327, CWE-338 |
| Authentication Weakness | `authentication` | CWE-287, CWE-347, CWE-384, CWE-521, CWE-798, CWE-916 |
| Access Control Violation | `access-control` | CWE-22, CWE-601, CWE-639, CWE-862, CWE-863 |
| Security Misconfiguration | `configuration`, `proxy` | CWE-16, CWE-200, CWE-209, CWE-489, CWE-614, CWE-693, CWE-732 |
| Insecure Deserialization | `integrity` | CWE-502 |
| Sensitive Data Exposure | `logging` | CWE-312, CWE-522, CWE-532 |
| Server-Side Request Forgery | `ssrf` | CWE-918 |
| Unrestricted File Upload | `upload` | CWE-434 |
| Insecure File Operation | `file-operations` | CWE-73, CWE-377 |
| XML External Entity (XXE) | — | CWE-611 |
| Denial of Service | `dos` | CWE-400, CWE-1333, CWE-409 |
| Improper Error Handling | `error-handling`, `async` | CWE-396, CWE-703, CWE-755 |
| Type Safety Violation | `type-safety` | CWE-697, CWE-704 |
| Insecure Design | `design` | CWE-20, CWE-307, CWE-330 |
| Memory Safety Violation | `deprecated` (for C/C++) | CWE-119, CWE-120, CWE-131, CWE-190, CWE-415, CWE-416, CWE-476 |
| Template Injection | — | CWE-1336 |
| Prototype Pollution | — | CWE-1321 |
| Unsafe Reflection | — | CWE-470 |

For rules that currently lack `subcategory`, derive `vulnerability_class` from the CWE using the table above.

Example rule change:

```yaml
# Before
- id: java-sql-injection
  message: "SQL injection vulnerability detected..."
  metadata:
    category: security
    cwe: CWE-89
    confidence: high

# After
- id: java-sql-injection
  message: "SQL injection vulnerability detected..."
  metadata:
    category: security
    cwe: CWE-89
    confidence: high
    subcategory: injection
    vulnerability_class: Injection Vulnerability
    owasp: "A03:2021"
```

### 2.2 Add OWASP Mappings

Currently 93/499 rules (19%) have OWASP. Target: 100% of applicable rules.

CWE-to-OWASP mapping table for bulk application:

| OWASP Category | CWEs |
|---|---|
| A01:2021 (Broken Access Control) | CWE-22, CWE-73, CWE-601, CWE-639, CWE-862, CWE-863, CWE-918 |
| A02:2021 (Cryptographic Failures) | CWE-208, CWE-259, CWE-295, CWE-310, CWE-312, CWE-319, CWE-322, CWE-326, CWE-327, CWE-338, CWE-522, CWE-798, CWE-916 |
| A03:2021 (Injection) | CWE-74, CWE-78, CWE-79, CWE-89, CWE-90, CWE-91, CWE-94, CWE-95, CWE-117, CWE-134, CWE-611, CWE-943, CWE-1321, CWE-1336 |
| A04:2021 (Insecure Design) | CWE-20, CWE-307, CWE-330, CWE-362, CWE-367 |
| A05:2021 (Security Misconfiguration) | CWE-16, CWE-200, CWE-209, CWE-276, CWE-489, CWE-614, CWE-693, CWE-732, CWE-942 |
| A06:2021 (Vulnerable Components) | CWE-477, CWE-1104 |
| A07:2021 (Auth Failures) | CWE-287, CWE-347, CWE-384, CWE-521 |
| A08:2021 (Data Integrity Failures) | CWE-345, CWE-353, CWE-434, CWE-494, CWE-502 |
| A09:2021 (Logging Failures) | CWE-532, CWE-778 |
| A10:2021 (SSRF) | CWE-918 |

Not all CWEs have a natural OWASP mapping (e.g., CWE-190 Integer Overflow, CWE-416 Use After Free). Memory safety and low-level CWEs (~30 rules, primarily in `c_cpp.yml`) should be left without OWASP rather than forcing an inaccurate mapping.

### 2.3 Add `subcategory` to Rules Missing It

Currently 103/499 rules (21%) have `subcategory`. The remaining 396 rules need it.

Derivation: Use the CWE→subcategory mapping from Phase 2.1 in reverse. For each rule, look up its CWE and assign the corresponding subcategory.

### 2.4 Add `references` to Rules

Currently 1/499 rules has explicit `references`. While the connector auto-generates CWE/OWASP URLs, adding references directly to rules enables:
- Framework-specific documentation links
- Language-specific remediation guides
- More targeted reference URLs than generic CWE pages

Priority: Add references to all rules with `framework` metadata (53 rules) first, linking to the framework's security documentation.

Example:

```yaml
- id: js-react-dangerous-html
  metadata:
    framework: react
    references:
      - https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
      - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
```

### 2.5 Acceptance Criteria

- [ ] All 499 rules have `subcategory` in metadata
- [ ] All 499 rules have `vulnerability_class` in metadata
- [ ] All applicable rules (~470) have `owasp` in metadata
- [ ] All 53 framework-specific rules have `references` with framework docs
- [ ] All existing tests pass (if any)

---

## Phase 3: Rule Message Rewrite

**Goal:** Every rule message follows the "What/Why/How" pattern so customers immediately understand the finding and what to do about it.

**Files to change:** All files in `socket_basics/rules/*.yml`

### 3.1 Message Format Standard

Every rule `message` should follow this three-part structure:

```
{What is wrong}. {Why it matters}. {How to fix it}.
```

**Example — sparse message (before):**
```yaml
message: "Route handler missing authentication/authorization check"
```

**Example — improved message (after):**
```yaml
message: >-
  Route handler is missing an authentication or authorization check. Without
  access control, any user can invoke this endpoint and access or modify
  protected resources. Add an authentication decorator (e.g., @login_required)
  or middleware check before processing the request.
```

### 3.2 Message Length Guidelines

| Severity | Target Length | Rationale |
|----------|-------------|-----------|
| Critical | 2-4 sentences (150-300 chars) | Urgent, needs clear remediation |
| High | 2-3 sentences (120-250 chars) | Important, needs fix guidance |
| Medium | 1-3 sentences (80-200 chars) | Informational with context |
| Low | 1-2 sentences (60-150 chars) | Awareness, minimal action |

### 3.3 Prioritization

Rewrite messages in this order:

1. **Critical severity rules** (most customer-visible, highest urgency) — 95 rules
2. **High severity rules with sparse messages** — 184 rules
3. **Medium severity rules** — 159 rules
4. **Low severity rules** — 61 rules

Within each severity tier, prioritize by CWE frequency (rules for CWE-89, CWE-78, CWE-79 first since they fire most often).

### 3.4 Add `fix` Metadata

Currently 2/499 rules have `fix`. The `fix` field provides a concise remediation instruction that appears separately from the message in the `detailedReport`.

Target: Add `fix` to all critical and high severity rules (279 rules).

Example:

```yaml
- id: python-sql-injection
  metadata:
    fix: >-
      Use parameterized queries with placeholders (cursor.execute("SELECT * FROM
      users WHERE id = %s", (user_id,))). For ORMs like SQLAlchemy or Django,
      use the query builder API instead of raw SQL.
```

The `fix` field should be **language-specific** and **actionable** — not a repeat of the message, but a concrete code-level instruction.

### 3.5 Acceptance Criteria

- [ ] All critical rules have 2-4 sentence messages with What/Why/How
- [ ] All high rules have 2-3 sentence messages with What/Why/How
- [ ] All critical + high rules have `fix` metadata
- [ ] No rule has a message shorter than 60 characters
- [ ] All existing tests pass

---

## Phase 4: Dataflow Traces + Advanced Enrichment

**Goal:** For taint-mode rules (SQL injection, command injection, XSS, etc.), show the data flow path from source to sink in the alert.

**Files to change:**
- `socket_basics/core/connector/opengrep/__init__.py` (CLI invocation + alert construction)

### 4.1 Enable `--dataflow-traces` Flag

Add the flag to the OpenGrep CLI invocation:

```python
# In the command construction (around line 162-174):
cmd = ['opengrep', '--json', '--dataflow-traces', '--output', out_file]
```

This causes OpenGrep to include `extra.dataflow_trace` in results for taint-mode rules, with structure:

```json
{
  "extra": {
    "dataflow_trace": {
      "taint_source": {
        "location": { "path": "...", "start": {...}, "end": {...} },
        "content": "request.args.get('id')"
      },
      "intermediate_vars": [
        {
          "location": { "path": "...", "start": {...}, "end": {...} },
          "content": "user_id = request.args.get('id')"
        }
      ],
      "taint_sink": {
        "location": { "path": "...", "start": {...}, "end": {...} },
        "content": "cursor.execute(query + user_id)"
      }
    }
  }
}
```

### 4.2 Extract and Format Dataflow Trace

In the alert construction block, after existing enrichment:

```python
_dataflow = (r.get('extra') or {}).get('dataflow_trace', {})
if _dataflow:
    _source = _dataflow.get('taint_source', {})
    _sink = _dataflow.get('taint_sink', {})
    _intermediates = _dataflow.get('intermediate_vars', [])

    alert['props']['dataflowTrace'] = {
        'source': {
            'content': _source.get('content', ''),
            'location': _format_location(_source.get('location', {})),
        },
        'sink': {
            'content': _sink.get('content', ''),
            'location': _format_location(_sink.get('location', {})),
        },
        'intermediates': [
            {
                'content': v.get('content', ''),
                'location': _format_location(v.get('location', {})),
            }
            for v in _intermediates
        ],
    }
```

### 4.3 Add Dataflow to `detailedReport`

For alerts with a dataflow trace, append a "Data Flow" section to the markdown:

```markdown
### Data Flow

1. **Source** (`app/routes.py:12`):
   ```python
   user_id = request.args.get('id')
   ```

2. **Intermediate** (`app/routes.py:15`):
   ```python
   query = "SELECT * FROM users WHERE id = " + user_id
   ```

3. **Sink** (`app/routes.py:16`):
   ```python
   cursor.execute(query)
   ```
```

This turns an abstract "SQL injection detected" into a concrete story: *here is where the user input enters, here is where it flows, and here is where it reaches the dangerous operation*.

### 4.4 Verify Performance Impact

The `--dataflow-traces` flag adds overhead to OpenGrep's analysis. Measure:
- Scan time on `app_tests/python` (baseline vs. with flag)
- Scan time on a larger real-world codebase
- Output JSON size increase

If overhead is >20% scan time increase, make the flag configurable via a config parameter (e.g., `opengrep_dataflow_traces: true/false`).

### 4.5 Acceptance Criteria

- [ ] `--dataflow-traces` is passed to OpenGrep
- [ ] Taint-mode alerts include `dataflowTrace` in props
- [ ] `detailedReport` includes "Data Flow" section for taint alerts
- [ ] Performance impact measured and documented
- [ ] Flag is configurable if overhead is significant

---

## Appendix A: CWE Catalog

Complete lookup table for all 90 CWEs referenced in our rules, sorted by frequency.

| CWE | Name | Customer Description | Category | Rules |
|-----|------|---------------------|----------|-------|
| CWE-327 | Broken or Risky Cryptographic Algorithm | The code uses a cryptographic algorithm that is known to be weak or insufficient. This may allow attackers to decrypt sensitive data or bypass integrity checks. | Cryptographic Weakness | 46 |
| CWE-89 | SQL Injection | User-supplied input is included in a SQL query without proper sanitization, potentially allowing attackers to read, modify, or delete database contents. | Injection Vulnerability | 32 |
| CWE-798 | Hard-coded Credentials | Credentials such as passwords, API keys, or cryptographic keys are embedded directly in source code, making them easily discoverable if the code is exposed. | Authentication Weakness | 32 |
| CWE-79 | Cross-Site Scripting (XSS) | User-supplied data is rendered in a web page without proper escaping, potentially allowing attackers to inject malicious scripts that execute in other users' browsers. | Injection Vulnerability | 21 |
| CWE-94 | Code Injection | User-controlled input is passed to a code evaluation function, potentially allowing attackers to execute arbitrary code on the server. | Injection Vulnerability | 20 |
| CWE-78 | OS Command Injection | User-supplied input is incorporated into an operating system command without proper sanitization, potentially allowing attackers to execute arbitrary system commands. | Injection Vulnerability | 19 |
| CWE-295 | Improper Certificate Validation | The application does not properly validate TLS/SSL certificates, which could allow attackers to intercept encrypted communications via man-in-the-middle attacks. | Cryptographic Weakness | 18 |
| CWE-22 | Path Traversal | User input is used to construct a file path without proper validation, potentially allowing attackers to access files outside the intended directory. | Access Control Violation | 18 |
| CWE-502 | Insecure Deserialization | The application deserializes data from an untrusted source without validation, which can lead to remote code execution or denial of service. | Insecure Deserialization | 17 |
| CWE-338 | Weak PRNG | The code uses a non-cryptographic random number generator for security-sensitive operations, producing predictable values that an attacker could guess. | Cryptographic Weakness | 17 |
| CWE-319 | Cleartext Transmission | Sensitive data is transmitted over an unencrypted channel, allowing network attackers to intercept and read the information. | Cryptographic Weakness | 16 |
| CWE-532 | Sensitive Information in Logs | Sensitive data such as passwords or tokens is written to log files, where it may be accessible to unauthorized parties. | Sensitive Data Exposure | 14 |
| CWE-601 | Open Redirect | The application redirects users to a URL from user input without validation, which can be exploited for phishing. | Access Control Violation | 13 |
| CWE-489 | Active Debug Code | Debug code or development-only features are left enabled in production, potentially exposing sensitive information. | Security Misconfiguration | 10 |
| CWE-862 | Missing Authorization | The application does not perform authorization checks before granting access to a resource, allowing unauthorized actions. | Access Control Violation | 9 |
| CWE-434 | Unrestricted File Upload | The application allows file uploads without validating type or content, potentially enabling upload of malicious code. | Unrestricted File Upload | 9 |
| CWE-732 | Incorrect Permission Assignment | Resources are created with overly permissive access rights, potentially exposing them to unauthorized access. | Security Misconfiguration | 7 |
| CWE-614 | Sensitive Cookie Without 'Secure' Flag | A sensitive cookie may be transmitted over unencrypted HTTP connections, making it interceptable by attackers. | Security Misconfiguration | 7 |
| CWE-352 | Cross-Site Request Forgery (CSRF) | The application does not verify that requests originated from its own interface, allowing forged requests from malicious sites. | Access Control Violation | 7 |
| CWE-347 | Improper Cryptographic Signature Verification | The application does not properly verify digital signatures, potentially allowing attackers to tamper with data. | Cryptographic Weakness | 7 |
| CWE-90 | LDAP Injection | User-supplied input is included in an LDAP query without sanitization, potentially allowing attackers to modify query logic. | Injection Vulnerability | 6 |
| CWE-703 | Improper Exception Handling | The application does not properly handle errors, which may lead to unexpected behavior or information disclosure. | Improper Error Handling | 6 |
| CWE-611 | XML External Entity (XXE) | The application parses XML that can reference external entities, potentially allowing attackers to read files or perform SSRF. | Injection Vulnerability | 6 |
| CWE-200 | Information Exposure | The application exposes sensitive information such as internal paths or configuration details to unauthorized users. | Security Misconfiguration | 6 |
| CWE-20 | Improper Input Validation | The application does not sufficiently validate user input, potentially allowing malformed data to trigger vulnerabilities. | Insecure Design | 5 |
| CWE-943 | NoSQL Injection | User-supplied input is included in a NoSQL query without sanitization, potentially allowing attackers to manipulate query logic. | Injection Vulnerability | 4 |
| CWE-755 | Improper Exception Handling | The application fails to properly handle unexpected situations, potentially leading to crashes or exploitable behavior. | Improper Error Handling | 4 |
| CWE-400 | Uncontrolled Resource Consumption | The application does not limit resource usage, making it vulnerable to denial-of-service attacks. | Denial of Service | 4 |
| CWE-377 | Insecure Temporary File | Temporary files are created insecurely, potentially allowing attackers to read or replace them. | Insecure File Operation | 4 |
| CWE-16 | Insecure Configuration | The application uses an insecure configuration that may weaken its security posture. | Security Misconfiguration | 4 |
| CWE-918 | Server-Side Request Forgery (SSRF) | The application fetches a remote resource using a user-controlled URL, allowing attackers to make requests to unintended destinations. | Server-Side Request Forgery | 3 |
| CWE-778 | Insufficient Logging | The application does not adequately log security events, making incident detection difficult. | Sensitive Data Exposure | 3 |
| CWE-639 | Insecure Direct Object Reference (IDOR) | A user-supplied identifier is used to look up resources without authorization checks, enabling unauthorized access. | Access Control Violation | 3 |
| CWE-521 | Weak Password Requirements | The application does not enforce strong password policies, making accounts vulnerable to brute-force attacks. | Authentication Weakness | 3 |
| CWE-416 | Use After Free | The application accesses memory after it has been freed, which can lead to crashes or code execution. | Memory Safety Violation | 3 |
| CWE-415 | Double Free | The application frees memory more than once, which can corrupt memory and allow code execution. | Memory Safety Violation | 3 |
| CWE-367 | TOCTOU Race Condition | A resource is checked and then used in separate operations, creating a window for attacker manipulation. | Insecure Design | 3 |
| CWE-326 | Inadequate Encryption Strength | Encryption uses an insufficient key length, making brute-force decryption feasible. | Cryptographic Weakness | 3 |
| CWE-310 | Cryptographic Issues | The application contains a general cryptographic weakness that may undermine data protection. | Cryptographic Weakness | 3 |
| CWE-287 | Improper Authentication | The application does not properly verify user identity, potentially allowing unauthorized access. | Authentication Weakness | 3 |
| CWE-250 | Execution with Unnecessary Privileges | The application runs with more permissions than required, increasing exploit impact. | Security Misconfiguration | 3 |
| CWE-209 | Error Message Information Leak | Error messages include sensitive details that could help an attacker plan further attacks. | Security Misconfiguration | 3 |
| CWE-190 | Integer Overflow | An arithmetic operation exceeds the integer range, potentially leading to buffer overflows or logic errors. | Memory Safety Violation | 3 |
| CWE-134 | Format String Vulnerability | User-supplied input is used as a format string, potentially allowing attackers to read or write memory. | Injection Vulnerability | 3 |
| CWE-1333 | ReDoS (Regular Expression Denial of Service) | A regular expression can be exploited with crafted input to cause catastrophic backtracking. | Denial of Service | 3 |
| CWE-120 | Buffer Overflow | Data is copied into a fixed-size buffer without checking input length, potentially enabling code execution. | Memory Safety Violation | 3 |
| CWE-119 | Buffer Overrun | Operations read or write beyond memory boundaries, which can cause crashes or enable code execution. | Memory Safety Violation | 3 |
| CWE-74 | Injection | User-supplied input is passed to a downstream interpreter without sanitization. | Injection Vulnerability | 2 |
| CWE-704 | Incorrect Type Conversion | An unsafe type conversion may lead to data truncation or memory corruption. | Type Safety Violation | 2 |
| CWE-697 | Incorrect Comparison | A flawed comparison can lead to logic bypasses or security check circumvention. | Type Safety Violation | 2 |
| CWE-693 | Protection Mechanism Failure | A security mechanism is absent or bypassable, reducing the application's security. | Security Misconfiguration | 2 |
| CWE-494 | Download Without Integrity Check | Code or updates are downloaded without verifying integrity, allowing supply of malicious code. | Insecure Deserialization | 2 |
| CWE-409 | Decompression Bomb | Compressed data is processed without size limits, potentially causing resource exhaustion. | Denial of Service | 2 |
| CWE-401 | Memory Leak | Allocated memory is never released, potentially leading to resource exhaustion. | Memory Safety Violation | 2 |
| CWE-384 | Session Fixation | Session identifiers are not regenerated after authentication, enabling session hijacking. | Authentication Weakness | 2 |
| CWE-362 | Race Condition | Shared resources are accessed without synchronization, potentially leading to data corruption. | Insecure Design | 2 |
| CWE-353 | Missing Integrity Check | Data is accepted without verifying integrity, allowing in-transit tampering. | Insecure Deserialization | 2 |
| CWE-322 | Key Exchange Without Authentication | Cryptographic key exchange lacks entity authentication, enabling man-in-the-middle attacks. | Cryptographic Weakness | 2 |
| CWE-312 | Cleartext Storage of Sensitive Information | Sensitive data is stored in plaintext, readable by anyone with storage access. | Sensitive Data Exposure | 2 |
| CWE-307 | Excessive Authentication Attempts | Failed login attempts are not limited, enabling brute-force attacks. | Insecure Design | 2 |
| CWE-276 | Incorrect Default Permissions | Resources are created with overly permissive defaults. | Security Misconfiguration | 2 |
| CWE-248 | Uncaught Exception | Unhandled exceptions may cause crashes or information disclosure. | Improper Error Handling | 2 |
| CWE-1336 | Template Injection | User input in template expressions can enable server-side code execution. | Template Injection | 2 |
| CWE-98 | Remote File Inclusion | User input controls which file is loaded, potentially enabling remote code execution. | Injection Vulnerability | 1 |
| CWE-95 | Eval Injection | User-supplied input is passed to eval(), allowing arbitrary code execution. | Injection Vulnerability | 1 |
| CWE-942 | Permissive CORS Policy | Overly permissive CORS allows malicious sites to access sensitive data. | Security Misconfiguration | 1 |
| CWE-926 | Improper Android Component Export | An Android component is exported without access restrictions. | Security Misconfiguration | 1 |
| CWE-916 | Weak Password Hashing | Passwords are hashed with a fast or weak algorithm, making cracking feasible. | Authentication Weakness | 1 |
| CWE-915 | Mass Assignment | Users can set arbitrary object attributes through input binding. | Access Control Violation | 1 |
| CWE-91 | XML/XPath Injection | User input in XML or XPath queries can alter query logic. | Injection Vulnerability | 1 |
| CWE-88 | Argument Injection | User input is passed as command arguments without delimiter neutralization. | Injection Vulnerability | 1 |
| CWE-863 | Incorrect Authorization | Authorization checks are implemented incorrectly, allowing unauthorized access. | Access Control Violation | 1 |
| CWE-73 | External File Path Control | User input determines which file to access, enabling arbitrary file operations. | Insecure File Operation | 1 |
| CWE-667 | Improper Locking | Lock mismanagement may lead to deadlocks or race conditions. | Insecure Design | 1 |
| CWE-522 | Insufficiently Protected Credentials | Credentials are stored or transmitted with inadequate protection. | Sensitive Data Exposure | 1 |
| CWE-479 | Signal Handler Safety | A signal handler calls a non-reentrant function, causing undefined behavior. | Memory Safety Violation | 1 |
| CWE-477 | Obsolete Function | A deprecated function with known weaknesses is used. | Security Misconfiguration | 1 |
| CWE-476 | NULL Pointer Dereference | A NULL pointer is used, causing a crash or undefined behavior. | Memory Safety Violation | 1 |
| CWE-470 | Unsafe Reflection | User input selects classes dynamically, enabling arbitrary code execution. | Injection Vulnerability | 1 |
| CWE-396 | Generic Exception Catch | Catching broad exceptions may mask security-relevant failures. | Improper Error Handling | 1 |
| CWE-345 | Insufficient Data Authenticity | Data is accepted without verifying its source or integrity. | Insecure Deserialization | 1 |
| CWE-330 | Insufficient Randomness | Random values are not unpredictable enough for their security context. | Insecure Design | 1 |
| CWE-259 | Hard-coded Password | A password is embedded in source code, easily discoverable and unchangeable. | Authentication Weakness | 1 |
| CWE-242 | Inherently Dangerous Function | An inherently unsafe function is called that cannot be used securely. | Memory Safety Violation | 1 |
| CWE-208 | Timing Side Channel | Timing differences in responses may allow attackers to extract secrets. | Cryptographic Weakness | 1 |
| CWE-1321 | Prototype Pollution | User input modifies JavaScript object prototypes, altering application logic. | Prototype Pollution | 1 |
| CWE-131 | Incorrect Buffer Size Calculation | Buffer size miscalculation can lead to overflow and code execution. | Memory Safety Violation | 1 |
| CWE-117 | Log Injection | Unsanitized input in logs allows forged entries or malicious content. | Sensitive Data Exposure | 1 |
| CWE-1104 | Unmaintained Third-Party Components | A dependency is no longer maintained, leaving vulnerabilities unpatched. | Security Misconfiguration | 1 |
| CWE-1059 | Insufficient Documentation | Inadequate code documentation makes security issues harder to find and fix. | Security Misconfiguration | 1 |

## Appendix B: Subcategory-to-Vulnerability-Class Mapping

For rules that already have `subcategory`, this table drives `vulnerability_class` assignment:

| subcategory | vulnerability_class | Rule Count |
|---|---|---|
| injection | Injection Vulnerability | 21 |
| crypto | Cryptographic Weakness | 16 |
| configuration | Security Misconfiguration | 11 |
| access-control | Access Control Violation | 9 |
| authentication | Authentication Weakness | 8 |
| error-handling | Improper Error Handling | 5 |
| integrity | Insecure Deserialization | 5 |
| design | Insecure Design | 5 |
| logging | Sensitive Data Exposure | 4 |
| deprecated | Memory Safety Violation | 3 |
| dos | Denial of Service | 3 |
| file-operations | Insecure File Operation | 2 |
| ssrf | Server-Side Request Forgery | 2 |
| type-safety | Type Safety Violation | 2 |
| upload | Unrestricted File Upload | 2 |
| xss | Cross-Site Scripting (XSS) | 1 |
| process | Injection Vulnerability | 1 |
| async | Improper Error Handling | 1 |
| proxy | Security Misconfiguration | 1 |
| performance | *(exclude — not security)* | 1 |

## Appendix C: Framework Metadata

53 rules have `framework` metadata across 32 unique frameworks. These should receive framework-specific `references` URLs in Phase 2.4.

| Framework | Rules | Documentation Link (for references) |
|---|---|---|
| phoenix | 8 | https://hexdocs.pm/phoenix/ |
| play | 4 | https://www.playframework.com/documentation/ |
| rails | 4 | https://guides.rubyonrails.org/security.html |
| aspnet | 2 | https://learn.microsoft.com/en-us/aspnet/core/security/ |
| express | 2 | https://expressjs.com/en/advanced/best-practice-security.html |
| jpa | 2 | https://docs.oracle.com/javaee/7/tutorial/persistence-intro.htm |
| react | 2 | https://react.dev/reference/react-dom/ |
| spring | 2 | https://docs.spring.io/spring-security/reference/ |
| otp | 2 | https://www.erlang.org/doc/design_principles/ |
| cowboy | 2 | https://ninenines.eu/docs/en/cowboy/ |
| coredata | 2 | https://developer.apple.com/documentation/coredata |
| *(22 others)* | 1 each | *(framework-specific docs)* |
