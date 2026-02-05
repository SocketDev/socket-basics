"""Helper functions for GitHub PR comment formatting."""

import re
from typing import Dict, Any, Optional, List
from pathlib import Path


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
    }

    ext = Path(filename).suffix.lower()
    return ext_map.get(ext, '')


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
        GitHub URL string
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
        alert_data.get('rule') or
        alert_data.get('type') or
        ''
    )

    return str(rule_name) if rule_name else ''
