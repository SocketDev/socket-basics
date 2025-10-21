"""Slack notifier formatting for Socket Tier1 reachability analysis."""

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


def _make_purl(comp: Dict[str, Any]) -> str:
    """Construct a best-effort purl from a component entry."""
    typ = comp.get('type')
    namespace = comp.get('namespace')
    name = comp.get('name') or comp.get('id')
    version = comp.get('version')
    if not name:
        return ''
    # Basic purl: pkg:type/namespace/name@version (percent-encode @ in namespace if needed)
    if namespace:
        # If namespace already contains @ (scoped npm), percent-encode
        ns = namespace.replace('@', '%40')
        p = f"pkg:{typ}/{ns}/{name}"
    else:
        p = f"pkg:{typ}/{name}"
    if version:
        p = p + f"@{version}"
    return p


def format_notifications(components_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format for Slack notifications - grouped by PURL and reachability."""
    from collections import defaultdict
    
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠', 
        'medium': '🟡',
        'low': '⚪'
    }
    
    # Group by PURL -> Reachability -> Findings
    purl_groups = defaultdict(lambda: {'reachable': [], 'unknown': [], 'error': [], 'unreachable': []})
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '').lower()
            reachability = str(props.get('reachability') or 'unknown').lower()
            
            # Count by severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Get trace data
            trace_raw = props.get('trace') or ''
            trace_str = ''
            if isinstance(trace_raw, list):
                trace_str = '\n'.join(str(x) for x in trace_raw)
            elif isinstance(trace_raw, str):
                trace_str = trace_raw
            
            # Truncate long traces
            if trace_str and len(trace_str) > 500:
                trace_str = trace_str[:500] + '\n...'
            
            finding = {
                'cve_id': cve_id,
                'severity': severity,
                'severity_order': severity_order.get(severity, 4),
                'severity_emoji': severity_emoji.get(severity, '⚪'),
                'trace': trace_str
            }
            
            # Group by reachability
            if reachability in purl_groups[purl]:
                purl_groups[purl][reachability].append(finding)
    
    # Sort findings within each group by severity (Critical -> High -> Medium -> Low)
    for purl in purl_groups:
        for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
            purl_groups[purl][reach_type].sort(key=lambda x: x['severity_order'])
    
    # Apply truncation at PURL level - keep top packages by highest severity
    result_limit = _get_slack_result_limit()
    total_results = sum(severity_counts.values())
    
    # Format for Slack
    if not purl_groups:
        content = "✅ No vulnerabilities found."
    else:
        # Add summary table
        content_lines = [
            "*Summary*",
            f"🔴 Critical: {severity_counts['critical']} | 🟠 High: {severity_counts['high']} | 🟡 Medium: {severity_counts['medium']} | ⚪ Low: {severity_counts['low']}",
            "",
            "*Details*",
            ""
        ]
        
        findings_shown = 0
        was_truncated = False
        
        # Sort PURLs by highest severity finding (critical first)
        purl_severity_list = []
        for purl in purl_groups:
            min_sev = 999
            for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
                for finding in purl_groups[purl][reach_type]:
                    if finding['severity_order'] < min_sev:
                        min_sev = finding['severity_order']
            purl_severity_list.append((min_sev, purl))
        
        # Sort ascending so critical (0) comes first
        purl_severity_list.sort(key=lambda x: x[0])
        
        for _, purl in purl_severity_list:
            if findings_shown >= result_limit:
                was_truncated = True
                break
                
            content_lines.append(f"*Package:* `{purl}`")
            content_lines.append("")
            
            # Reachable findings (highest priority)
            if purl_groups[purl]['reachable']:
                content_lines.append("*Reachable*")
                for finding in purl_groups[purl]['reachable']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    content_lines.append(f"{finding['severity_emoji']} *{finding['cve_id']}*: {finding['severity'].upper()}")
                    if finding['trace']:
                        content_lines.append(f"```\n{finding['trace']}\n```")
                    findings_shown += 1
                content_lines.append("")
            
            # Unknown reachability findings
            if purl_groups[purl]['unknown'] and findings_shown < result_limit:
                content_lines.append("*Unknown*")
                for finding in purl_groups[purl]['unknown']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    content_lines.append(f"{finding['severity_emoji']} *{finding['cve_id']}*: {finding['severity'].upper()}")
                    findings_shown += 1
                content_lines.append("")
            
            # Error reachability findings
            if purl_groups[purl]['error'] and findings_shown < result_limit:
                content_lines.append("*Error*")
                for finding in purl_groups[purl]['error']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    content_lines.append(f"{finding['severity_emoji']} *{finding['cve_id']}*: {finding['severity'].upper()}")
                    findings_shown += 1
                content_lines.append("")
            
            # Unreachable findings (lowest priority)
            if purl_groups[purl]['unreachable'] and findings_shown < result_limit:
                content_lines.append("*Unreachable*")
                for finding in purl_groups[purl]['unreachable']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    content_lines.append(f"{finding['severity_emoji']} *{finding['cve_id']}*: {finding['severity'].upper()}")
                    findings_shown += 1
                content_lines.append("")
        
        content = "\n".join(content_lines)
        
        # Add truncation notice if needed
        if was_truncated:
            content += f"\n⚠️ *Showing {findings_shown} of {total_results} findings (highest severity first).*"
    
    return [{
        'title': 'Socket Tier1 Reachability',
        'content': content
    }]