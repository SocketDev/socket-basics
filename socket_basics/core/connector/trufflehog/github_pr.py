#!/usr/bin/env python3
"""
GitHub PR notifier for TruffleHog results.
Formats results with markdown for better GitHub display of secret detection findings.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any], config=None) -> List[Dict[str, Any]]:
    """Format for GitHub PR comments - detailed with markdown formatting."""
    rows = []
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', ''))
            file_path = str(props.get('filePath', '-'))
            line = str(props.get('lineNumber', ''))
            redacted = str(props.get('redactedValue', ''))
            verified = props.get('verified', False)
            
            # Format with markdown for better GitHub display
            status = '✅ **VERIFIED**' if verified else '⚠️ *Unverified*'
            file_display = f"`{file_path}`"
            if line:
                file_display += f":{line}"
            
            rows.append([
                f"**{detector}**",
                f"*{severity}*",
                status,
                file_display,
                f"`{redacted}`" if redacted else '-'
            ])
    
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
    
    # Build title with repo/branch/commit info from config
    title_parts = ["Socket Security Results"]
    if config:
        if config.repo:
            title_parts.append(config.repo)
        if config.branch:
            title_parts.append(config.branch)
        if config.commit_hash:
            title_parts.append(config.commit_hash)
    
    title = " - ".join(title_parts)
    
    # Count total findings for summary
    total_findings = len(rows)
    
    # Add summary section with scanner findings
    summary_content = f"""## Summary

| Scanner | Findings |
|---------|----------|
| TruffleHog Secrets | {total_findings} |

## Details

{content}"""
    
    # Wrap content with HTML comment markers for section updates
    wrapped_content = f"""<!-- trufflehog-secrets start -->
# {title}

{summary_content}
<!-- trufflehog-secrets end -->"""
    
    return [{
        'title': title,
        'content': wrapped_content
    }]