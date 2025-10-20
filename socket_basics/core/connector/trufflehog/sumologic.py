#!/usr/bin/env python3
"""
SumoLogic notifier for TruffleHog results.
Formats results in structured logging format suitable for log parsing of secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for SumoLogic - structured logging format."""
    rows = []
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', ''))
            file_path = str(props.get('filePath', ''))
            line = str(props.get('lineNumber', ''))
            verified = props.get('verified', False)
            secret_type = str(props.get('secretType', ''))
            
            # Key-value format suitable for log parsing
            rows.append([
                f"detector={detector}",
                f"severity={severity}",
                f"secret_type={secret_type}",
                f"file={file_path}",
                f"line={line}",
                f"verified={verified}",
                f"scanner=trufflehog"
            ])
    
    # Format as structured data
    if not rows:
        content = "No secrets found."
    else:
        headers = ['Detector', 'Severity', 'Type', 'File', 'Line', 'Verified', 'Scanner']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    return [{
        'title': 'TruffleHog Secret Events',
        'content': content
    }]