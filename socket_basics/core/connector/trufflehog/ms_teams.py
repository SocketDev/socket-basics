#!/usr/bin/env python3
"""
Microsoft Teams notifier for TruffleHog results.
Formats results in clean tabular format suitable for Teams display of secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for Microsoft Teams - clean tabular format."""
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
            
            location = f"{file_path}:{line}" if line else file_path
            # Truncate for Teams
            if len(location) > 60:
                location = location[:57] + '...'
            
            rows.append([
                detector,
                severity,
                'Verified' if verified else 'Unverified',
                location,
                redacted[:30] + '...' if len(redacted) > 30 else redacted  # Truncate for Teams
            ])
    
    # Format as structured data
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