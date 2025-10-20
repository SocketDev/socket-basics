"""Jira notifier formatting for Socket Tier1 reachability analysis."""

from typing import Dict, Any, List


def _detect_language_from_purl(purl: str) -> str:
    """Detect programming language from PURL (Package URL)."""
    # Extract the package type from PURL format: pkg:type/namespace/name@version
    if not purl or not purl.startswith('pkg:'):
        return 'JavaScript'  # Default fallback for most npm packages
    
    try:
        # Split by : to get the type part
        parts = purl.split(':', 2)  # ['pkg', 'type', 'rest']
        if len(parts) >= 2:
            package_type = parts[1].split('/')[0]  # Get type before any /
            
            # Map package types to Jira-supported languages
            type_to_language = {
                'npm': 'JavaScript',
                'pypi': 'Python',
                'maven': 'Java',
                'gradle': 'Java', 
                'nuget': 'C#',
                'gem': 'Ruby',
                'go': 'Go',
                'cargo': 'Rust',  # Not in Jira supported list, will fallback
                'composer': 'PHP',
                'swift': 'Swift',
                'cocoapods': 'Swift',
                'hackage': 'Haskell',
                'hex': 'Erlang',
                'cran': 'R',
                'cpan': 'Perl',
            }
            
            detected_lang = type_to_language.get(package_type.lower(), 'JavaScript')
            
            # Ensure the language is in Jira's supported list
            jira_supported = [
                'ActionScript', 'Ada', 'AppleScript', 'bash', 'C', 'C#', 'C++', 
                'CSS', 'Erlang', 'Go', 'Groovy', 'Haskell', 'HTML', 'JavaScript', 
                'JSON', 'Lua', 'Nyan', 'Objc', 'Perl', 'PHP', 'Python', 'R', 
                'Ruby', 'Scala', 'SQL', 'Swift', 'VisualBasic', 'XML', 'YAML'
            ]
            
            if detected_lang in jira_supported:
                return detected_lang
            else:
                return 'JavaScript'  # Safe fallback
                
    except Exception:
        pass
    
    return 'JavaScript'  # Default fallback


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
    """Format for Jira tickets - using panels for better layout control."""
    
    # Define severity ranking for sorting
    severity_rank = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3
    }
    
    # Collect all alerts with component info
    all_alerts = []
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '').lower()
            reachability = str(props.get('reachability') or '').lower()
            
            # Format trace data 
            trace_raw = props.get('trace') or ''
            trace_str = ''
            if isinstance(trace_raw, list):
                trace_str = '\n'.join(str(x) for x in trace_raw)
            elif isinstance(trace_raw, str):
                trace_str = trace_raw
            
            all_alerts.append({
                'cve_id': cve_id,
                'severity': severity,
                'reachability': reachability,
                'purl': purl,
                'trace_str': trace_str
            })
    
    if not all_alerts:
        content = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "No reachability issues found."}]
                }
            ]
        }
    else:
        # Sort alerts by severity (Critical -> High -> Medium -> Low)
        sorted_alerts = sorted(
            all_alerts,
            key=lambda x: severity_rank.get(x['severity'], 999)
        )
        
        panels = []
        
        for alert in sorted_alerts:
            # Map severity to Jira priority
            jira_priority = {
                'critical': 'Highest',
                'high': 'High',
                'medium': 'Medium', 
                'low': 'Low'
            }.get(alert['severity'], 'Medium')
            
            # Determine panel color based on priority
            panel_type = {
                'Highest': 'error',
                'High': 'warning',
                'Medium': 'note',
                'Low': 'info'
            }.get(jira_priority, 'note')
            
            # Build panel content
            panel_content = [
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": f"🔒 {alert['cve_id']}", "marks": [{"type": "strong"}]}]
                },
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Severity: ", "marks": [{"type": "strong"}]},
                        {"type": "text", "text": jira_priority}
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Reachability: ", "marks": [{"type": "strong"}]},
                        {"type": "text", "text": alert['reachability'].upper() if alert['reachability'] == 'reachable' else alert['reachability']}
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Package: ", "marks": [{"type": "strong"}]},
                        {"type": "text", "text": alert['purl'], "marks": [{"type": "code"}]}
                    ]
                }
            ]
            
            # Add trace if reachable and trace exists
            if alert['reachability'] == 'reachable' and alert['trace_str']:
                # Dynamically determine language from PURL
                language = _detect_language_from_purl(alert['purl'])
                
                panel_content.extend([
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "Call Trace:", "marks": [{"type": "strong"}]}
                        ]
                    },
                    {
                        "type": "codeBlock",
                        "attrs": {"language": language.lower()},
                        "content": [{"type": "text", "text": alert['trace_str']}]
                    }
                ])
            
            # Create the panel
            panels.append({
                "type": "panel",
                "attrs": {"panelType": panel_type},
                "content": panel_content
            })
            
            # Add a rule/divider between issues
            panels.append({
                "type": "rule"
            })
        
        # Remove the last rule
        if panels and panels[-1]["type"] == "rule":
            panels.pop()
        
        content = {
            "type": "doc",
            "version": 1,
            "content": panels
        }
    
    return [{
        'title': 'Socket Tier1 Reachability Analysis',
        'content': content
    }]