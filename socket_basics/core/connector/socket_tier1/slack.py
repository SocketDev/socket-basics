"""Slack notifier formatting for Socket Tier1 reachability analysis."""

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


def format_notifications(components_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format for Slack notifications - concise with emojis."""
    rows = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '')
            reachability = str(props.get('reachability') or '').lower()
            
            # Add severity emojis and reachability emojis for Slack
            severity_lower = severity.lower()
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢'
            }.get(severity_lower, '⚪')
            
            reach_emoji = {
                'reachable': '🔥',
                'unreachable': '✅',
                'unknown': '❓'
            }.get(reachability, '⚪')
            
            # Truncate PURL for Slack readability
            short_purl = purl[:50] + '...' if len(purl) > 50 else purl
            
            rows.append([
                cve_id,
                f"{severity_emoji} {severity}",
                f"{reach_emoji} {reachability}",
                short_purl,
                'Yes' if reachability == 'reachable' else 'No'
            ])
    
    # Format as markdown table for Slack
    if not rows:
        content = "No Socket Tier1 vulnerabilities found."
    else:
        headers = ['CVE/GHSA', 'Severity', 'Reachability', 'Package', 'Has Trace']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    return [{
        'title': 'Socket Tier1 Reachability Analysis',
        'content': content
    }]