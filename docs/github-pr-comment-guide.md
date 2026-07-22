# GitHub PR Comment Guide

Socket Basics delivers **beautifully formatted, actionable GitHub PR comments** that help developers quickly understand and address security findings.

## 🌟 Universal Features

These enhancements work across **all scanner types**:
- ✅ **Socket Tier 1** (Reachability Analysis)
- ✅ **SAST** (OpenGrep/Semgrep)
- ✅ **Container Scanning** (when container findings are available)
- ✅ **Secret Detection** (TruffleHog)
- ✅ **Future OSS Tools** (via centralized architecture)

All scanners share the same UX enhancements for a consistent, professional experience.

> [!NOTE]
> Container-scanning UX is still supported by Socket Basics, but the current
> pre-built GitHub Action image currently ships _without_ Trivy while we
> evaluate the safest way to bundle it with Basics again. For the current Trivy
> status, version guidance, and temporary self-service path, see
> [Local Installation](local-installation.md#trivy-container-scanning).

## 🎯 Quick Start

**Want the enhanced experience?** You already have it! All features are **enabled by default** with the standard workflow setup — see the [Quick Start in README](../README.md#-quick-start---github-actions).

## ✨ Features

### 1. Clickable File Links (`pr_comment_links_enabled`)

**Default:** `true`

Jump directly to vulnerable code in GitHub with one click.

**Before:**
```
owasp-goat - server.js 72:12-75:6
  -> express routes/auth.js 45:2
```

**After:**
```
owasp-goat - [server.js 72:12-75:6](https://github.com/owner/repo/blob/abc123/server.js#L72-L75)
  -> express [routes/auth.js 45:2](https://github.com/owner/repo/blob/abc123/routes/auth.js#L45)
```

**Disable:**
```yaml
pr_comment_links_enabled: 'false'
```

---

### 2. Collapsible Sections (`pr_comment_collapse_enabled`)

**Default:** `true` (critical auto-expands, others collapse)

Organize findings with expandable sections for easy scanning.

**Before:**
```markdown
#### pkg:npm/lodash@4.17.20

🔴 CVE-2021-23337: CRITICAL
...

🟠 CVE-2021-23338: HIGH
...
```

**After:**
```markdown
<details open>
<summary><strong>pkg:npm/lodash@4.17.20</strong> (🔴 Critical: 1 | 🟠 High: 1)</summary>

🔴 CVE-2021-23337: CRITICAL
...

🟠 CVE-2021-23338: HIGH
...

</details>
```

**Options:**
```yaml
# Disable collapsible sections entirely
pr_comment_collapse_enabled: 'false'

# Keep collapsible but expand everything
pr_comment_collapse_enabled: 'true'
pr_comment_collapse_non_critical: 'false'
```

---

### 3. Syntax Highlighting (`pr_comment_code_fencing_enabled`)

**Default:** `true`

Language-aware code blocks based on file extension.

**Before:**
```
owasp-goat - server.js 72:12-75:6
  -> express routes/auth.js 45:2
```

**After:**
````markdown
```javascript
owasp-goat - [server.js 72:12-75:6](https://github.com/owner/repo/blob/abc123/server.js#L72-L75)
  -> express [routes/auth.js 45:2](https://github.com/owner/repo/blob/abc123/routes/auth.js#L45)
```
````

**Supported languages:**
- JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`)
- Python (`.py`)
- Go (`.go`)
- Java (`.java`)
- Ruby (`.rb`)
- PHP (`.php`)
- And 20+ more...

**Disable:**
```yaml
pr_comment_code_fencing_enabled: 'false'
```

---

### 4. Explicit Rule Names (`pr_comment_show_rule_names`)

**Default:** `true`

Clearly identify which security rule was triggered.

**Before:**
```
🔴 CVE-2021-23337: CRITICAL
```

**After:**
```
🔴 CVE-2021-23337: CRITICAL
**Rule**: `CVE-2021-23337`
```

**Disable:**
```yaml
pr_comment_show_rule_names: 'false'
```

---

### 5. CVE Links & CVSS Scores

**Default:** Always enabled (automatic for CVE/vulnerability findings)

Make vulnerability IDs clickable and display CVSS scores for better risk assessment.

**Before:**
```markdown
🔴 CVE-2021-23337: CRITICAL
```

**After:**
```markdown
🔴 **[CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337)** • CRITICAL (CVSS 9.8)
```

**How it works:**
- CVE IDs automatically become clickable links to the National Vulnerability Database (NVD)
- CVSS scores are displayed when available from the scanner
- Works for Socket Tier 1 and container/CVE scanning when those findings are present
- Missing CVSS scores are gracefully omitted (no breaking changes)

**Example with different formats:**
```markdown
# With CVSS score
🔴 **[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)** • CRITICAL (CVSS 10.0)

# Without CVSS score (not available)
🟠 **[CVE-2021-23338](https://nvd.nist.gov/vuln/detail/CVE-2021-23338)** • HIGH

# Non-CVE vulnerabilities (GHSA, etc.)
🔴 **GHSA-abcd-1234-efgh** • CRITICAL
```

**Benefits:**
- One-click access to detailed vulnerability information
- CVSS scores provide standardized risk context
- Helps developers prioritize remediation efforts
- Links to official NVD entries with full CVE details

---

### 6. Full Scan Link at Top

**Default:** Always enabled (when URL available)

Quick access to the complete scan report.

**Before:**
```markdown
# Socket Security Tier 1 Results

### Summary
🔴 Critical: 3 | 🟠 High: 14 | 🟡 Medium: 0 | ⚪ Low: 0

### Details
...

---
🔗 [View Full Socket Scan](https://socket.dev/scan/123)
```

**After:**
```markdown
# Socket Security Tier 1 Results

🔗 **[View Full Socket Scan Report](https://socket.dev/scan/123)**

---

### Summary
🔴 Critical: 3 | 🟠 High: 14 | 🟡 Medium: 0 | ⚪ Low: 0

### Details
...
```

---

### 7. Auto-Labels with Colors (`pr_labels_enabled`)

**Default:** `true`

Automatically tag PRs with severity-based labels **and matching colors**.

**Labels added (with automatic color assignment):**
- `security: critical` 🔴 - Red (`#D73A4A`)
- `security: high` 🟠 - Orange (`#D93F0B`)
- `security: medium` 🟡 - Yellow (`#FBCA04`)
- `security: low` ⚪ - Light gray (`#E4E4E4`)

**Smart color detection:**
Labels are automatically created with colors matching the severity emojis. If you customize label names, the system intelligently detects severity keywords and applies appropriate colors:

```yaml
pr_label_critical: 'vulnerability: critical'  # Gets red color automatically
pr_label_high: 'security-high'               # Gets orange color automatically
```

**How it works:**
- Each run keeps only the current highest-severity managed PR label: critical → high → medium → low
- Stale managed severity labels from earlier runs are removed automatically
- If a later run has no active findings, the managed severity label is removed
- Labels are created automatically if they don't exist
- Existing labels are not modified (preserves your customizations)
- Requires a token with `repo` scope to create new labels; without it, label creation may fail (comments still post)

**Customize:**
```yaml
pr_labels_enabled: 'true'
pr_label_critical: 'vulnerability: critical'
pr_label_high: 'vulnerability: high'
pr_label_medium: 'vulnerability: medium'
pr_label_low: 'vulnerability: low'
```

**Disable:**
```yaml
pr_labels_enabled: 'false'
```

---

### 8. Logo Branding

**Default:** Always enabled

Every PR comment section includes the Socket shield logo inline with the title header for consistent branding.

```markdown
## <img src="...socket-logo.png" width="24" height="24"> Socket Security Tier 1
```

The logo is a 32px PNG rendered at 24x24 for retina-crisp display, with a transparent background that works in both GitHub light and dark modes.

---

### 9. All-Clear Comment Updates

When a later Socket Basics run no longer has active findings for a previously-reported scanner section, the existing PR comment section is updated in place instead of being left stale or deleted.

**Behavior:**
- Existing Socket-managed sections are preserved for auditability
- Stale findings content is replaced with a short all-clear message
- This keeps the PR history readable while making it obvious that the latest run is clean

**Example all-clear message:**
```text
✅ Socket Basics found no active findings in the latest run.
```

---

## 📋 Configuration Reference

### All Options

| Option | Default | Type | Description |
|--------|---------|------|-------------|
| `pr_comment_links_enabled` | `true` | boolean | Enable clickable file/line links |
| `pr_comment_collapse_enabled` | `true` | boolean | Enable collapsible sections |
| `pr_comment_collapse_non_critical` | `true` | boolean | Auto-collapse non-critical findings |
| `pr_comment_code_fencing_enabled` | `true` | boolean | Enable syntax highlighting |
| `pr_comment_show_rule_names` | `true` | boolean | Show explicit rule names |
| `pr_labels_enabled` | `true` | boolean | Add severity-based labels to PRs |
| `pr_label_critical` | `"security: critical"` | string | Label name for critical findings |
| `pr_label_high` | `"security: high"` | string | Label name for high findings |
| `pr_label_medium` | `"security: medium"` | string | Label name for medium findings |
| `pr_label_low` | `"security: low"` | string | Label name for low findings |

### Configuration Methods

**1. GitHub Actions (Recommended)**

Add these parameters to the `with:` block in your workflow (see [Quick Start](../README.md#-quick-start---github-actions)):
```yaml
pr_comment_links_enabled: 'true'
pr_label_critical: 'security: critical'
```

**2. CLI Arguments**
```bash
socket-basics \
  --pr-comment-links \
  --pr-comment-collapse \
  --pr-label-critical "security: critical"
```

**3. Environment Variables**
```bash
export INPUT_PR_COMMENT_LINKS_ENABLED=true
export INPUT_PR_LABEL_CRITICAL="security: critical"
```

---

## 🎨 Common Configurations

All examples below show only the `with:` parameters to add to your workflow. See the [Quick Start](../README.md#-quick-start---github-actions) for the full workflow setup.

### Default (Recommended)

Everything enabled with sensible defaults — no extra parameters needed.

### Minimal (Plaintext)

Simple text output without enhancements:
```yaml
pr_comment_links_enabled: 'false'
pr_comment_collapse_enabled: 'false'
pr_comment_code_fencing_enabled: 'false'
pr_comment_show_rule_names: 'false'
pr_labels_enabled: 'false'
```

### Enterprise (Custom Labels)

Match your organization's label taxonomy:
```yaml
pr_label_critical: 'vulnerability: critical'
pr_label_high: 'vulnerability: high'
pr_label_medium: 'vulnerability: medium'
```

### Security Team (All Expanded)

Show all details expanded for thorough review:
```yaml
pr_comment_collapse_non_critical: 'false'
```

### OSS Project (Minimize Noise)

Keep comments clean and collapsed:
```yaml
pr_comment_collapse_non_critical: 'true'
pr_label_critical: 'security'
pr_label_high: 'security'
pr_label_medium: 'security'
```

---

## 🚀 Migration Guide

### Already using Socket Basics?

**Good news!** All new features are **opt-out** with sensible defaults.

**Your existing workflows will automatically benefit from:**
- ✅ Clickable file links
- ✅ Collapsible sections
- ✅ Syntax highlighting
- ✅ Rule names
- ✅ Auto-labels

**No changes required** unless you want to customize behavior.

### Disable specific features

If you prefer the old style, simply disable individual features:

```yaml
# Keep everything except labels
pr_labels_enabled: 'false'

# Or disable everything
pr_comment_links_enabled: 'false'
pr_comment_collapse_enabled: 'false'
pr_comment_code_fencing_enabled: 'false'
pr_comment_show_rule_names: 'false'
pr_labels_enabled: 'false'
```

---

## 💡 Tips & Best Practices

### For Open Source Projects
- Use simple label taxonomy (e.g., all `security`)
- Keep non-critical findings collapsed
- Enable all visual enhancements for contributor UX

### For Enterprise Teams
- Match your organization's label taxonomy
- Consider expanding all findings for security review
- Customize labels to integrate with existing workflows

### For Security Teams
- Expand all findings by default
- Enable all enhancements for maximum detail
- Use specific label names for automation

---

## 🏗️ Architecture & Extensibility

### Centralized PR Comment Logic

All PR comment enhancements are powered by a **shared helper module** at:
```
socket_basics/core/notification/github_pr_helpers.py
```

This centralized approach provides:
- **Consistent UX** across all scanner types
- **Zero code duplication** - one implementation for all formatters
- **Easy integration** for new OSS security tools

### Adding Your Own Security Tool

Socket Basics is designed to support **any security scanner**. To add enhancements to a new tool:

```python
from socket_basics.core.notification import github_pr_helpers as helpers

def format_notifications(data, config=None):
    # 1. Get feature flags (handles all config sources automatically)
    flags = helpers.get_feature_flags(config)

    # 2. Use shared utilities to build your content
    file_link = helpers.format_file_location_link(
        filepath, line_start=line_num, repository=flags['repository'],
        commit_hash=flags['commit_hash'], enable_links=flags['enable_links']
    )

    code_block = helpers.format_code_block(
        code_snippet, filepath=filepath,
        enable_fencing=flags['enable_code_fencing']
    )

    collapsible = helpers.create_collapsible_section(
        title, content, severity_counts,
        auto_expand=(critical and not flags['collapse_non_critical'])
    )

    # 3. Wrap in the standard PR comment section (logo, scan link, markers)
    wrapped = helpers.wrap_pr_comment_section(
        'my-scanner', title, body_content, flags['full_scan_url']
    )

    return [{'title': title, 'content': wrapped}]
```

**That's it!** Your tool instantly gets:
- ✅ Clickable file/line links
- ✅ Collapsible sections
- ✅ Syntax highlighting
- ✅ Logo branding and full scan report link
- ✅ Idempotent comment updates (via HTML markers)
- ✅ Configuration management

### Shared Constants

Use shared severity constants for consistency:
```python
severity_order = helpers.SEVERITY_ORDER  # {'critical': 0, 'high': 1, ...}
severity_emoji = helpers.SEVERITY_EMOJI  # {'critical': '🔴', 'high': '🟠', ...}
```

---

## 📚 Related Documentation

- [Main README](../README.md)
- [GitHub Actions Integration](github-action.md)
- [Configuration Examples](../socket_config_example.json)
- [Shared Helper Module](../socket_basics/core/notification/github_pr_helpers.py)
