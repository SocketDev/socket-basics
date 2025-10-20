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
    """Format for GitHub PR comments - detailed with markdown formatting."""
    rows = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '')
            reachability = str(props.get('reachability') or '').lower()
            
            # Format with markdown for better GitHub display
            trace_raw = props.get('trace') or ''
            trace_str = ''
            if isinstance(trace_raw, list):
                trace_str = '\n'.join(str(x) for x in trace_raw)
            elif isinstance(trace_raw, str):
                trace_str = trace_raw
            
            if reachability == 'reachable' and trace_str:
                # Convert newlines to <br> tags for GitHub markdown tables
                trace_formatted = trace_str.replace('\n', '<br>')
                # Use <pre> tags for better code formatting as requested
                if len(trace_formatted) > 300:
                    trace_formatted = trace_formatted[:300] + '...'
                trace_formatted = f"<pre>{trace_formatted}</pre>"
            else:
                trace_formatted = f"`{purl}`"
            
            rows.append([
                f"**{cve_id}**",
                f"*{severity}*",
                f"**{reachability.upper()}**" if reachability == 'reachable' else reachability,
                f"`{purl}`",
                trace_formatted
            ])
    
    # Create markdown table
    if not rows:
        content = "No reachability issues found."
    else:
        headers = ['CVE/GHSA', 'Severity', 'Reachability', 'PURL', 'Trace']
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        content_rows = []
        for row in rows:
            content_rows.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
        
        content = '\n'.join([header_row, separator_row] + content_rows)
    
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
    
    # Count total findings for summary
    total_findings = len(rows)
    
    # Add summary section with scanner findings
    summary_content = f"""## Summary

| Scanner | Findings |
|---------|----------|
| Socket Tier1 | {total_findings} |

## Details

{content}"""
    
    # Wrap content with HTML comment markers for section updates
    wrapped_content = f"""<!-- socket-tier1 start -->
# {title}

{summary_content}
<!-- socket-tier1 end -->"""
    
    return [{
        'title': title,
        'content': wrapped_content
    }]