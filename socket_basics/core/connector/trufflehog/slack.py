#!/usr/bin/env python3
"""
Slack notifier for TruffleHog results.
Formats results concisely with emojis for visual appeal in secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for Slack notifications - concise with emojis."""
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
            
            # Add emojis for Slack
            severity_lower = severity.lower()
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢'
            }.get(severity_lower, '⚪')
            
            status_emoji = '✅' if verified else '⚠️'
            
            # Truncate file path for Slack
            short_path = file_path[:40] + '...' if len(file_path) > 40 else file_path
            location = f"{short_path}:{line}" if line else short_path
            
            rows.append([
                detector,
                f"{severity_emoji} {severity}",
                f"{status_emoji} {'Verified' if verified else 'Unverified'}",
                location,
                redacted[:20] + '...' if len(redacted) > 20 else redacted
            ])
    
    # Format as markdown table for Slack
    if not rows:
        content = "No secrets found."
    else:
        headers = ['Detector', 'Severity', 'Status', 'Location', 'Secret']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    return [{
        'title': 'TruffleHog Secret Detection Results',
        'content': content
    }]