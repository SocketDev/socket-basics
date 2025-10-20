"""Microsoft Sentinel notifier formatting for Socket Tier1 reachability analysis."""

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
    """Format for Microsoft Sentinel - structured for SIEM ingestion."""
    rows = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            ghsa_id = str(props.get('ghsaId', ''))
            cve_only = str(props.get('cveId', ''))
            severity = str(a.get('severity') or props.get('severity') or '')
            reachability = str(props.get('reachability') or '')
            
            # More structured format for SIEM
            rows.append([
                cve_id,
                severity,
                reachability,
                purl,
                ghsa_id,
                cve_only,
                comp_name,
                str(props.get('undeterminableReachability', False))
            ])
    
    # Format as structured data for MS Sentinel
    if not rows:
        content = "No Socket Tier1 vulnerabilities found."
    else:
        headers = ['ID', 'Severity', 'Reachability', 'PURL', 'GHSA', 'CVE', 'Component', 'Undeterminable']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
    return [{
        'title': 'Socket Tier1 Vulnerability Findings',
        'content': content
    }]