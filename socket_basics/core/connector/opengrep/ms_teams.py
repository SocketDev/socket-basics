#!/usr/bin/env python3
"""
Microsoft Teams notifier for OpenGrep results.
Formats results in clean tabular format suitable for Teams.
"""

from pathlib import Path
from typing import Dict, Any, List
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


def format_notifications(groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Format for Microsoft Teams - return formatted sections grouped by subtype."""
    tables = []
    
    # Map subtypes to friendly display names
    subtype_names = {
        'sast-python': 'Socket SAST Python',
        'sast-javascript': 'Socket SAST JavaScript', 
        'sast-golang': 'Socket SAST Go',
        'sast-java': 'Socket SAST Java',
        'sast-php': 'Socket SAST PHP',
        'sast-ruby': 'Socket SAST Ruby',
        'sast-csharp': 'Socket SAST C#',
        'sast-dotnet': 'Socket SAST .NET',
        'sast-c': 'Socket SAST C',
        'sast-cpp': 'Socket SAST C++',
        'sast-kotlin': 'Socket SAST Kotlin',
        'sast-scala': 'Socket SAST Scala',
        'sast-swift': 'Socket SAST Swift',
        'sast-rust': 'Socket SAST Rust',
        'sast-elixir': 'Socket SAST Elixir',
        'sast-generic': 'Socket SAST Generic'
    }
    
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    for subtype, items in groups.items():
        if not items:  # Skip empty groups
            continue
            
        findings = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for item in items:
            c = item['component']
            a = item['alert']
            props = a.get('props', {}) or {}
            full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
            
            try:
                file_name = Path(full_path).name
            except Exception:
                file_name = full_path
            
            severity = a.get('severity', '').lower()
            
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
            
            code_snippet = (props.get('codeSnippet', '') or '')[:150]
            if len(props.get('codeSnippet', '') or '') > 150:
                code_snippet += '...'
            
            findings.append((
                severity_order.get(severity, 4),
                {
                    'rule': props.get('ruleId', a.get('title', '')),
                    'severity': a.get('severity', ''),
                    'severity_emoji': severity_emoji,
                    'file_name': file_name,
                    'full_path': full_path,
                    'lines': f"{props.get('startLine','')}-{props.get('endLine','')}",
                    'code': code_snippet
                }
            ))
        
        # Sort by severity and extract findings
        findings.sort(key=lambda x: x[0])
        findings = [f[1] for f in findings]
        
        # Apply truncation
        result_limit = _get_ms_teams_result_limit()
        total_results = len(findings)
        was_truncated = False
        
        if total_results > result_limit:
            logger.info(f"Truncating MS Teams OpenGrep results from {total_results} to {result_limit} (prioritized by severity)")
            findings = findings[:result_limit]
            was_truncated = True
        
        # Create MS Teams-formatted content
        display_name = subtype_names.get(subtype, f"Socket {subtype.upper()}")
        
        if not findings:
            content = f"✅ No issues found."
        else:
            # Create summary table
            content_lines = [
                "**Summary**\n\n",
                f"🔴 Critical: {severity_counts['critical']} | 🟠 High: {severity_counts['high']} | 🟡 Medium: {severity_counts['medium']} | ⚪ Low: {severity_counts['low']}\n\n",
                "---\n\n",
                "**Details**\n\n"
            ]
            
            # Format findings list
            for idx, f in enumerate(findings, 1):
                content_lines.append(
                    f"{f['severity_emoji']} **{f['rule']}** ({f['severity'].upper()})\n\n"
                    f"**File:** `{f['file_name']}`\n\n"
                    f"**Path:** {f['full_path']}\n\n"
                    f"**Lines:** {f['lines']}"
                )
                if f['code'].strip():
                    content_lines.append(f"\n\n**Code:** `{f['code']}`")
                content_lines.append("\n\n---\n")
            
            content = "".join(content_lines)
            
            # Add truncation notice if needed
            if was_truncated:
                content += f"\n⚠️ **Results truncated to {result_limit} highest severity findings (total: {total_results}). View more in full scan.**"
        
        tables.append({
            'title': display_name,
            'content': content
        })
    
    # Return list of tables - one per language group
    return tables