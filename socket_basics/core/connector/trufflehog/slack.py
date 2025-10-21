#!/usr/bin/env python3
"""
Slack notifier for TruffleHog results.
Formats results concisely with emojis for visual appeal in secret detection.
"""

from typing import Dict, Any, List
from pathlib import Path
import logging
import yaml

logger = logging.getLogger(__name__)


def _get_slack_result_limit() -> int:
    """Get the result limit for Slack notifications."""
    try:
        notifications_yaml = Path(__file__).parent.parent.parent.parent / 'notifications.yaml'
        with open(notifications_yaml, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('settings', {}).get('result_limits', {}).get('slack', 50)
    except Exception as e:
        logger.warning(f"Could not load Slack result limit from notifications.yaml: {e}, using default 50")
        return 50


def format_notifications(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format for Slack notifications - concise with emojis."""
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
            
            # Add emojis for Slack
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '⚪'
            }.get(severity, '⚪')
            
            # Truncate file path for Slack
            short_path = file_path[:40] + '...' if len(file_path) > 40 else file_path
            location = f"{short_path}:{line}" if line else short_path
            
            findings.append((
                severity_order.get(severity, 4),
                {
                    'detector': detector,
                    'severity': severity,
                    'severity_emoji': severity_emoji,
                    'verified': verified,
                    'location': location,
                    'redacted': redacted[:20] + '...' if len(redacted) > 20 else redacted
                }
            ))
    
    # Sort by severity
    findings.sort(key=lambda x: x[0])
    findings = [f[1] for f in findings]
    
    # Apply truncation
    result_limit = _get_slack_result_limit()
    total_results = len(findings)
    was_truncated = False
    
    if total_results > result_limit:
        logger.info(f"Truncating Slack TruffleHog results from {total_results} to {result_limit} (prioritized by severity)")
        findings = findings[:result_limit]
        was_truncated = True
    
    # Format for Slack
    if not findings:
        content = "✅ No secrets found."
    else:
        # Add summary table
        content_lines = [
            "*Summary*",
            f"🔴 Critical: {severity_counts['critical']} | 🟠 High: {severity_counts['high']} | 🟡 Medium: {severity_counts['medium']} | ⚪ Low: {severity_counts['low']}",
            "",
            "*Details*",
            ""
        ]
        
        for idx, f in enumerate(findings, 1):
            status = 'Verified' if f['verified'] else 'Unverified'
            content_lines.append(
                f"{f['severity_emoji']} *{f['detector']}* ({f['severity'].upper()})\n"
                f"Status: *{status}*\n"
                f"Location: `{f['location']}`\n"
                f"Secret: `{f['redacted']}`\n"
            )
        
        content = "\n".join(content_lines)
        
        # Add truncation notice if needed
        if was_truncated:
            content += f"\n⚠️ *Results truncated to {result_limit} highest severity findings (total: {total_results}). View more in full scan.*"
    
    return [{
        'title': 'Socket Secret Detection',
        'content': content
    }]