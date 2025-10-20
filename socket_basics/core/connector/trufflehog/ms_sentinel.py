#!/usr/bin/env python3
"""
Microsoft Sentinel notifier for TruffleHog results.
Formats results structured for SIEM ingestion of secret detection findings.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for Microsoft Sentinel - structured for SIEM ingestion."""
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
            risk_level = str(props.get('riskLevel', ''))
            
            # More structured format for SIEM
            rows.append([
                detector,
                severity,
                secret_type,
                file_path,
                line,
                str(verified),
                risk_level,
                'source-code'
            ])
    
    # Format as structured data
    if not rows:
        content = "No secrets found."
    else:
        headers = ['Detector', 'Severity', 'SecretType', 'FilePath', 'LineNumber', 'Verified', 'RiskLevel', 'ExposureType']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    return [{
        'title': 'TruffleHog Secret Findings',
        'content': content
    }]