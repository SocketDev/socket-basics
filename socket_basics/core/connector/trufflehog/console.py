#!/usr/bin/env python3
"""
Console notifier for TruffleHog results.
Formats results for human-readable console output with truncated content for secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for console output - human readable with truncated content."""
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
            
            # Truncate for console readability
            short_path = file_path[:30] + '...' if len(file_path) > 30 else file_path
            location = f"{short_path}:{line}" if line else short_path
            
            short_secret = redacted[:15] + '...' if len(redacted) > 15 else redacted
            status = 'OK' if verified else 'WARN'
            
            rows.append([
                detector,
                severity,
                status,
                location,
                short_secret
            ])
    
    # Format as a table using tabulate
    from tabulate import tabulate
    
    headers = ['Detector', 'Severity', 'Status', 'Location', 'Secret']
    table_content = tabulate(rows, headers=headers, tablefmt='grid') if rows else "No secrets found."
    
    return [{
        'title': 'TruffleHog Secret Detection Results',
        'content': table_content
    }]