#!/usr/bin/env python3
"""
Microsoft Teams notifier for TruffleHog results.
Formats results in clean tabular format suitable for Teams display of secret detection.
"""

from typing import Dict, Any, List
from pathlib import Path
import logging
import yaml

logger = logging.getLogger(__name__)


def _get_ms_teams_result_limit() -> int:
    """Get the result limit for MS Teams notifications."""
    try:
        notifications_yaml = Path(__file__).parent.parent.parent.parent / 'notifications.yaml'
        with open(notifications_yaml, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('settings', {}).get('result_limits', {}).get('ms_teams', 50)
    except Exception as e:
        logger.warning(f"Could not load MS Teams result limit from notifications.yaml: {e}, using default 50")
        return 50


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for Microsoft Teams - clean list format."""
    findings = []
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', '')).lower()
            file_path = str(props.get('filePath', '-'))
            line = str(props.get('lineNumber', ''))
            redacted = str(props.get('redactedValue', ''))
            verified = props.get('verified', False)
            
            # Count by severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Add severity emojis
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '⚪'
            }.get(severity, '⚪')
            
            location = f"{file_path}:{line}" if line else file_path
            # Truncate for Teams
            if len(location) > 60:
                location = location[:57] + '...'
            
            findings.append((
                severity_order.get(severity, 4),
                {
                    'detector': detector,
                    'severity': severity,
                    'severity_emoji': severity_emoji,
                    'verified': verified,
                    'location': location,
                    'redacted': redacted[:30] + '...' if len(redacted) > 30 else redacted
                }
            ))
    
    # Sort by severity
    findings.sort(key=lambda x: x[0])
    findings = [f[1] for f in findings]
    
    # Apply truncation
    result_limit = _get_ms_teams_result_limit()
    total_results = len(findings)
    was_truncated = False
    
    if total_results > result_limit:
        logger.info(f"Truncating MS Teams TruffleHog results from {total_results} to {result_limit} (prioritized by severity)")
        findings = findings[:result_limit]
        was_truncated = True
    
    # Format for MS Teams
    if not findings:
        content = "✅ No secrets found."
    else:
        # Add summary table
        content_lines = [
            "**Summary**\n\n",
            f"🔴 Critical: {severity_counts['critical']} | 🟠 High: {severity_counts['high']} | 🟡 Medium: {severity_counts['medium']} | ⚪ Low: {severity_counts['low']}\n\n",
            "---\n\n",
            "**Details**\n\n"
        ]
        
        for idx, f in enumerate(findings, 1):
            status = 'Verified' if f['verified'] else 'Unverified'
            content_lines.append(
                f"{f['severity_emoji']} **{f['detector']}** ({f['severity'].upper()})\n\n"
                f"**Status:** {status}\n\n"
                f"**Location:** `{f['location']}`\n\n"
                f"**Secret:** `{f['redacted']}`\n\n---\n"
            )
        
        content = "".join(content_lines)
        
        # Add truncation notice if needed
        if was_truncated:
            content += f"\n⚠️ **Results truncated to {result_limit} highest severity findings (total: {total_results}). View more in full scan.**"
    
    return [{
        'title': 'Socket Secret Detection',
        'content': content
    }]