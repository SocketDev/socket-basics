"""Console notifier formatting for Socket Tier1 reachability analysis."""

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
    """Format for console output - human readable with full trace information."""
    rows = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '')
            reachability = str(props.get('reachability') or '')
            
            # Truncate for console readability
            short_purl = purl[:40] + '...' if len(purl) > 40 else purl
            
            # Show actual trace data for reachable vulnerabilities
            trace_data = str(props.get('trace') or '')
            if reachability == 'reachable' and trace_data.strip():
                # Format full trace with proper line breaks
                trace_lines = trace_data.strip().split('\n')
                formatted_trace = '\n'.join(trace_lines)
            else:
                formatted_trace = ''
            
            rows.append([
                cve_id,
                severity,
                reachability,
                short_purl,
                formatted_trace
            ])
    
    # Format as a table using tabulate
    from tabulate import tabulate
    
    headers = ['CVE/GHSA', 'Severity', 'Reachability', 'Package', 'Trace']
    table_content = tabulate(rows, headers=headers, tablefmt='grid') if rows else "No Socket Tier1 vulnerabilities found."
    
    return [{
        'title': 'Socket Tier1 Reachability Analysis',
        'content': table_content
    }]