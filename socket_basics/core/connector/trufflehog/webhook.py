#!/usr/bin/env python3
"""
Webhook notifier for TruffleHog results.
Formats results for generic webhook consumption with flexible structured format for secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for generic webhook - flexible structured format."""
    rows = []
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', ''))
            file_path = str(props.get('filePath', ''))
            line = str(props.get('lineNumber', ''))
            redacted = str(props.get('redactedValue', ''))
            verified = props.get('verified', False)
            secret_type = str(props.get('secretType', ''))
            
            rows.append([
                detector,
                severity,
                secret_type,
                file_path,
                line,
                redacted,
                str(verified),
                'trufflehog'
            ])
    
    # Format as structured data
    if not rows:
        content = "No secrets found."
    else:
        headers = ['Detector', 'Severity', 'SecretType', 'FilePath', 'Line', 'RedactedValue', 'Verified', 'Scanner']
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