"""JSON notifier formatting for Socket Tier1 reachability analysis."""

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
    """Format for JSON output - complete structured data."""
    rows = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '')
            reachability = str(props.get('reachability') or '')
            
            # Include trace data for JSON
            trace_raw = props.get('trace') or ''
            trace_str = ''
            if isinstance(trace_raw, list):
                trace_str = '\n'.join(str(x) for x in trace_raw)
            elif isinstance(trace_raw, str):
                trace_str = trace_raw
            
            rows.append([
                cve_id,
                severity,
                reachability,
                purl,
                str(props.get('ghsaId', '')),
                str(props.get('cveId', '')),
                comp_name,
                str(comp.get('version', '')),
                trace_str,
                str(props.get('undeterminableReachability', False))
            ])
    
    # Format as JSON data structure
    if not rows:
        content = "No Socket Tier1 vulnerabilities found."
    else:
        import json
        # For JSON, create a structured array of objects
        structured_data = []
        headers = ['ID', 'Severity', 'Reachability', 'PURL', 'GHSA', 'CVE', 'Component', 'Version', 'Trace', 'Undeterminable']
        for row in rows:
            obj = {}
            for i, header in enumerate(headers):
                if i < len(row):
                    obj[header] = row[i]
            structured_data.append(obj)
        
        content = json.dumps(structured_data, indent=2)
    
    return [{
        'title': 'Socket Tier1 Reachability Analysis',
        'content': content
    }]