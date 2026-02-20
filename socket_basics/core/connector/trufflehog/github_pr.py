#!/usr/bin/env python3
"""
GitHub PR notifier for TruffleHog results.
Formats results with markdown for better GitHub display of secret detection findings.
"""

from typing import Dict, Any, List
from socket_basics.core.notification import github_pr_helpers as helpers


def format_notifications(mapping: Dict[str, Any], config=None) -> List[Dict[str, Any]]:
    """Format for GitHub PR comments - detailed with markdown formatting."""
    # Get feature flags from config (using shared helper)
    flags = helpers.get_feature_flags(config)
    enable_links = flags['enable_links']
    repository = flags['repository']
    commit_hash = flags['commit_hash']
    full_scan_url = flags['full_scan_url']

    # Use shared severity constants
    severity_order = helpers.SEVERITY_ORDER
    severity_emoji = helpers.SEVERITY_EMOJI

    rows = []
    
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', '')).lower()
            file_path = str(props.get('filePath', '-'))
            line = str(props.get('lineNumber', ''))
            redacted = str(props.get('redactedValue', ''))
            verified = props.get('verified', False)
            
            # Format with markdown for better GitHub display
            status = '✅ **VERIFIED**' if verified else '⚠️ *Unverified*'

            # Create clickable file location link
            line_num = int(line) if line and line.isdigit() else None
            file_display = helpers.format_file_location_link(
                file_path,
                line_start=line_num,
                repository=repository,
                commit_hash=commit_hash,
                enable_links=enable_links
            )

            # Add severity emoji
            emoji = severity_emoji.get(severity, '⚪')

            rows.append((
                severity_order.get(severity, 4),
                [
                    f"**{detector}**",
                    f"{emoji} *{severity.upper()}*",
                    status,
                    file_display,
                    f"`{redacted}`" if redacted else '-'
                ]
            ))
    
    # Sort by severity (critical first)
    rows.sort(key=lambda x: x[0])
    rows = [row[1] for row in rows]
    
    # Create markdown table
    if not rows:
        content = "No secrets detected."
    else:
        headers = ['Detector', 'Severity', 'Status', 'Location', 'Secret']
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        content_rows = []
        for row in rows:
            content_rows.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    # Build title - just scanner name (repo/branch context already visible in PR)
    title = "Socket Secret Scanning"

    # Count total findings for summary
    total_findings = len(rows)

    # Add summary section with scanner findings
    summary_content = f"""### Summary

| Scanner | Findings |
|---------|----------|
| TruffleHog Secrets | {total_findings} |

### Details

{content}"""

    # Wrap in standard PR comment section
    wrapped_content = helpers.wrap_pr_comment_section(
        'trufflehog-secrets', title, summary_content, full_scan_url
    )
    
    return [{
        'title': title,
        'content': wrapped_content
    }]