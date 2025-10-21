"""GitHub PR notifier formatting for Socket Tier1 reachability analysis."""

from typing import Dict, Any, List


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


def format_notifications(components_list: List[Dict[str, Any]], config=None) -> List[Dict[str, Any]]:
    """Format for GitHub PR comments - grouped by PURL and reachability."""
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
                'trace': trace_str
            }
            
            # Group by reachability
            if reachability in purl_groups[purl]:
                purl_groups[purl][reachability].append(finding)
    
    # Sort findings within each group by severity (Critical -> High -> Medium -> Low)
    for purl in purl_groups:
        for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
            purl_groups[purl][reach_type].sort(key=lambda x: x['severity_order'])
    
    # Build content
    if not purl_groups:
        content = "✅ No reachability issues found."
    else:
        content_lines = []
        
        # Add summary
        content_lines.append("### Summary")
        content_lines.append(f"{severity_emoji.get('critical', '🔴')} Critical: {severity_counts['critical']} | "
                            f"{severity_emoji.get('high', '🟠')} High: {severity_counts['high']} | "
                            f"{severity_emoji.get('medium', '🟡')} Medium: {severity_counts['medium']} | "
                            f"{severity_emoji.get('low', '⚪')} Low: {severity_counts['low']}")
        content_lines.append("")
        content_lines.append("### Details")
        content_lines.append("")
        
        # Sort PURLs by highest severity finding (critical first)
        purl_severity_list = []
        for purl in purl_groups:
            min_sev = 999
            for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
                for finding in purl_groups[purl][reach_type]:
                    if finding['severity_order'] < min_sev:
                        min_sev = finding['severity_order']
            purl_severity_list.append((min_sev, purl))
        
        purl_severity_list.sort(key=lambda x: x[0])
        
        for _, purl in purl_severity_list:
            content_lines.append(f"#### `{purl}`")
            content_lines.append("")
            
            # Reachable findings (highest priority)
            if purl_groups[purl]['reachable']:
                content_lines.append("**Reachable**")
                content_lines.append("")
                for finding in purl_groups[purl]['reachable']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")
                    if finding['trace']:
                        content_lines.append("```")
                        content_lines.append(finding['trace'])
                        content_lines.append("```")
                    content_lines.append("")
            
            # Unknown reachability findings
            if purl_groups[purl]['unknown']:
                content_lines.append("**Unknown**")
                content_lines.append("")
                for finding in purl_groups[purl]['unknown']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")
                content_lines.append("")
            
            # Error reachability findings
            if purl_groups[purl]['error']:
                content_lines.append("**Error**")
                content_lines.append("")
                for finding in purl_groups[purl]['error']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")
                content_lines.append("")
            
            # Unreachable findings (lowest priority)
            if purl_groups[purl]['unreachable']:
                content_lines.append("**Unreachable**")
                content_lines.append("")
                for finding in purl_groups[purl]['unreachable']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")
                content_lines.append("")
        
        content = '\n'.join(content_lines)
    
    # Build title with repo/branch/commit info from config
    title_parts = ["Socket Security Tier 1 Results"]
    if config:
        if config.repo:
            title_parts.append(config.repo)
        if config.branch:
            title_parts.append(config.branch)
        if config.commit_hash:
            title_parts.append(config.commit_hash)
    
    title = " - ".join(title_parts)
    
    # Count total findings
    total_findings = sum(severity_counts.values())
    
    # Content already includes summary and details sections
    summary_content = content
    
    # Wrap content with HTML comment markers for section updates
    wrapped_content = f"""<!-- socket-tier1 start -->
# {title}

{summary_content}
<!-- socket-tier1 end -->"""
    
    return [{
        'title': title,
        'content': wrapped_content
    }]