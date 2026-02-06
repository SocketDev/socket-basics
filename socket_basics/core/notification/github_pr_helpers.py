"""Shared helper functions for GitHub PR comment formatting across all scanners.

This module provides centralized utilities for:
- Clickable file/line links
- Collapsible sections with severity summaries
- Language-aware code fencing
- Rule name extraction
- Configuration-based feature flags

These utilities are designed to work with any security scanner (SAST, SCA, secrets, containers).
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path


# ============================================================================
# Severity Constants (shared across all scanners)
# ============================================================================

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '⚪'
}


# ============================================================================
# Configuration Helper
# ============================================================================

def get_feature_flags(config) -> Dict[str, Any]:
    """Extract PR comment feature flags from config object.

    Args:
        config: Configuration object (may be None)

    Returns:
        Dictionary of feature flags with defaults
    """
    if not config:
        return {
            'enable_links': True,
            'enable_collapse': True,
            'collapse_non_critical': True,
            'enable_code_fencing': True,
            'show_rule_names': True,
            'repository': '',
            'commit_hash': '',
            'full_scan_url': None
        }

    return {
        'enable_links': config.get('pr_comment_links_enabled', True),
        'enable_collapse': config.get('pr_comment_collapse_enabled', True),
        'collapse_non_critical': config.get('pr_comment_collapse_non_critical', True),
        'enable_code_fencing': config.get('pr_comment_code_fencing_enabled', True),
        'show_rule_names': config.get('pr_comment_show_rule_names', True),
        'repository': config.repo if hasattr(config, 'repo') else '',
        'commit_hash': config.commit_hash if hasattr(config, 'commit_hash') else '',
        'full_scan_url': config.get('full_scan_html_url') if config else None
    }


# ============================================================================
# Language Detection
# ============================================================================

def detect_language_from_filename(filename: str) -> str:
    """Detect programming language from file extension.

    Args:
        filename: File path or name

    Returns:
        Markdown language identifier for code fencing
    """
    ext_map = {
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.py': 'python',
        '.go': 'go',
        '.java': 'java',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.swift': 'swift',
        '.rs': 'rust',
        '.ex': 'elixir',
        '.exs': 'elixir',
        '.erl': 'erlang',
        '.sh': 'bash',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.json': 'json',
        '.xml': 'xml',
        '.html': 'html',
        '.css': 'css',
        '.sql': 'sql',
        '.dockerfile': 'dockerfile',
        '.Dockerfile': 'dockerfile',
    }

    ext = Path(filename).suffix.lower()

    # Special case for Dockerfile (no extension)
    if Path(filename).name.lower() in ['dockerfile', 'dockerfile.dev', 'dockerfile.prod']:
        return 'dockerfile'

    return ext_map.get(ext, '')


# ============================================================================
# GitHub URL Building
# ============================================================================

def build_github_file_url(
    repository: str,
    commit_hash: str,
    filepath: str,
    line_start: Optional[int] = None,
    line_end: Optional[int] = None
) -> str:
    """Build a GitHub URL to a specific file and line range.

    Args:
        repository: GitHub repository (e.g., "owner/repo")
        commit_hash: Git commit hash
        filepath: Relative file path from repository root
        line_start: Starting line number (optional)
        line_end: Ending line number (optional)

    Returns:
        GitHub URL string (empty if repository/commit missing)
    """
    if not repository or not commit_hash:
        return ''

    # Clean filepath (remove leading ./ or /)
    clean_path = filepath.lstrip('./')

    # Base URL
    url = f"https://github.com/{repository}/blob/{commit_hash}/{clean_path}"

    # Add line anchor
    if line_start is not None:
        if line_end is not None and line_end != line_start:
            url += f"#L{line_start}-L{line_end}"
        else:
            url += f"#L{line_start}"

    return url


def format_file_location_link(
    filepath: str,
    line_start: Optional[int] = None,
    line_end: Optional[int] = None,
    repository: str = '',
    commit_hash: str = '',
    enable_links: bool = True
) -> str:
    """Format a file location as plain text or clickable markdown link.

    Args:
        filepath: File path
        line_start: Starting line number
        line_end: Ending line number
        repository: GitHub repository
        commit_hash: Git commit hash
        enable_links: Whether to create clickable links

    Returns:
        Formatted string (plain or markdown link)
    """
    # Build display text
    location_text = f"`{filepath}`"
    if line_start is not None:
        if line_end is not None and line_end != line_start:
            location_text += f" **Lines {line_start}-{line_end}**"
        else:
            location_text += f" **Line {line_start}**"

    # Add link if enabled and metadata available
    if enable_links and repository and commit_hash:
        url = build_github_file_url(repository, commit_hash, filepath, line_start, line_end)
        if url:
            # Make the filepath clickable
            if line_start is not None:
                if line_end is not None and line_end != line_start:
                    return f"[`{filepath}` Lines {line_start}-{line_end}]({url})"
                else:
                    return f"[`{filepath}` Line {line_start}]({url})"
            else:
                return f"[`{filepath}`]({url})"

    return location_text


# ============================================================================
# Trace Formatting (for Socket Tier 1 reachability)
# ============================================================================

def format_trace_with_links(
    trace_lines: List[str],
    repository: str,
    commit_hash: str,
    enable_links: bool = True
) -> str:
    """Format trace lines with clickable GitHub links.

    Args:
        trace_lines: List of trace strings (format: "package - filename.ext 10:5-15:20")
        repository: GitHub repository
        commit_hash: Git commit hash
        enable_links: Whether to create clickable links

    Returns:
        Formatted trace string with optional links
    """
    if not trace_lines:
        return ''

    formatted_lines = []

    for line in trace_lines:
        if not enable_links:
            formatted_lines.append(line)
            continue

        # Parse trace format: "package_name - filename.js 72:12-75:6"
        # or "  -> module_name path/to/file.py 45:2"
        # Note: package names can contain dashes, so we look for " - " (space-dash-space) as separator

        # Try format with " - " separator first
        match = re.match(
            r'^(\s*)(.+?)\s+-\s+([^\s]+)\s+(\d+):(\d+)(?:-(\d+):(\d+))?$',
            line
        )

        if not match:
            # Try format with "-> " prefix (no " - " separator)
            match = re.match(
                r'^(\s+->)\s+(.+?)\s+([^\s]+)\s+(\d+):(\d+)(?:-(\d+):(\d+))?$',
                line
            )

        if match:
            prefix = match.group(1)
            package = match.group(2).strip()
            filename = match.group(3)
            line_start = int(match.group(4))
            col_start = match.group(5)
            line_end = int(match.group(6)) if match.group(6) else line_start
            col_end = match.group(7)

            # Build GitHub URL
            github_url = build_github_file_url(
                repository, commit_hash, filename, line_start, line_end
            )

            if github_url:
                # Create markdown link
                location = f"{line_start}:{col_start}"
                if line_end != line_start or (col_end and col_end != col_start):
                    location += f"-{line_end}:{col_end}"

                # Format based on whether it has the " - " separator or "-> " prefix
                if ' - ' in line or line.strip().startswith('->'):
                    # Preserve original structure
                    if '-> ' in prefix:
                        formatted = f"{prefix} {package} [{filename} {location}]({github_url})"
                    else:
                        formatted = f"{prefix}{package} - [{filename} {location}]({github_url})"
                else:
                    formatted = f"{prefix}{package} - [{filename} {location}]({github_url})"

                formatted_lines.append(formatted)
            else:
                formatted_lines.append(line)
        else:
            # Couldn't parse, keep original
            formatted_lines.append(line)

    return '\n'.join(formatted_lines)


# ============================================================================
# Collapsible Sections
# ============================================================================

def build_severity_summary(severity_counts: Dict[str, int]) -> str:
    """Build a severity summary string with emojis.

    Args:
        severity_counts: Dictionary mapping severity levels to counts

    Returns:
        Formatted severity summary (e.g., "🔴 Critical: 3 | 🟠 High: 14")
    """
    parts = []
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            emoji = SEVERITY_EMOJI.get(severity, '⚪')
            parts.append(f"{emoji} {severity.capitalize()}: {count}")

    return " | ".join(parts) if parts else "No issues"


def create_collapsible_section(
    title: str,
    content: str,
    severity_counts: Optional[Dict[str, int]] = None,
    auto_expand: bool = False
) -> str:
    """Create a collapsible <details> section with optional severity summary.

    Args:
        title: Section title (will be bolded)
        content: Section content (markdown)
        severity_counts: Optional severity counts to show in summary
        auto_expand: Whether to auto-expand the section

    Returns:
        Markdown collapsible section
    """
    summary_line = f"<strong>{title}</strong>"

    if severity_counts:
        severity_summary = build_severity_summary(severity_counts)
        summary_line += f" ({severity_summary})"

    open_attr = ' open' if auto_expand else ''

    return f"""<details{open_attr}>
<summary>{summary_line}</summary>

{content}

</details>

"""


# ============================================================================
# Code Fencing
# ============================================================================

def format_code_block(
    code: str,
    filepath: Optional[str] = None,
    language: Optional[str] = None,
    enable_fencing: bool = True
) -> str:
    """Format code in a language-aware fenced code block.

    Args:
        code: Code content
        filepath: Optional file path to detect language from
        language: Explicit language override
        enable_fencing: Whether to add code fencing

    Returns:
        Formatted code block
    """
    if not code or not code.strip():
        return ''

    if not enable_fencing:
        return code

    # Determine language
    lang = language or ''
    if not lang and filepath:
        lang = detect_language_from_filename(filepath)

    return f"```{lang}\n{code}\n```"


# ============================================================================
# Rule Name Extraction
# ============================================================================

def extract_rule_name(alert_data: Dict[str, Any]) -> str:
    """Extract rule name from alert data.

    Args:
        alert_data: Alert dictionary

    Returns:
        Rule name or empty string
    """
    # Check various possible sources
    props = alert_data.get('props', {}) or {}

    # Priority order for rule names
    rule_name = (
        props.get('rule') or
        props.get('rule_name') or
        props.get('ruleName') or
        props.get('ruleId') or
        alert_data.get('rule') or
        alert_data.get('type') or
        alert_data.get('title') or
        ''
    )

    return str(rule_name) if rule_name else ''


# ============================================================================
# Scan Link Formatting
# ============================================================================

def format_scan_link_section(full_scan_url: Optional[str]) -> str:
    """Format the full scan report link section.

    Args:
        full_scan_url: URL to full scan report

    Returns:
        Formatted markdown section (empty if no URL)
    """
    if not full_scan_url:
        return ''

    return f"\n\n🔗 **[View Full Socket Scan Report]({full_scan_url})**\n\n---\n"
