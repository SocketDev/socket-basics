"""Jira notifier formatting for Socket Tier1 reachability analysis."""

from typing import Dict, Any, List
from pathlib import Path
import logging
import yaml

logger = logging.getLogger(__name__)


def _get_jira_result_limit() -> int:
    """Get the result limit for Jira notifications."""
    try:
        notifications_yaml = Path(__file__).parent.parent.parent.parent / 'notifications.yaml'
        with open(notifications_yaml, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('settings', {}).get('result_limits', {}).get('jira', 30)
    except Exception as e:
        logger.warning(f"Could not load Jira result limit from notifications.yaml: {e}, using default 30")
        return 30


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
    """Format for Jira tickets - grouped by PURL and reachability."""
    from collections import defaultdict
    
    # Define severity ranking for sorting
    severity_rank = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3
    }
    
    # Group by PURL -> Reachability -> Findings
    purl_groups = defaultdict(lambda: {'reachable': [], 'unknown': [], 'error': [], 'unreachable': []})
    
    for comp in components_list:
        comp_name = str(comp.get('name') or comp.get('id') or '-')
        
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            purl = str(props.get('purl') or _make_purl(comp) or comp_name)
            cve_id = str(props.get('ghsaId') or props.get('cveId') or a.get('title') or '')
            severity = str(a.get('severity') or props.get('severity') or '').lower()
            reachability = str(props.get('reachability') or 'unknown').lower()
            
            # Format trace data 
            trace_raw = props.get('trace') or ''
            trace_str = ''
            if isinstance(trace_raw, list):
                trace_str = '\n'.join(str(x) for x in trace_raw)
            elif isinstance(trace_raw, str):
                trace_str = trace_raw
            
            # Truncate long traces
            if trace_str and len(trace_str) > 2000:
                trace_str = trace_str[:2000] + '\n...'
            
            finding = {
                'cve_id': cve_id,
                'severity': severity,
                'severity_rank': severity_rank.get(severity, 999),
                'trace_str': trace_str
            }
            
            # Group by reachability
            if reachability in purl_groups[purl]:
                purl_groups[purl][reachability].append(finding)
    
    # Sort findings within each group by severity (Critical -> High -> Medium -> Low)
    for purl in purl_groups:
        for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
            purl_groups[purl][reach_type].sort(key=lambda x: x['severity_rank'])
    
    if not purl_groups:
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
        # Apply truncation at finding level
        result_limit = _get_jira_result_limit()
        total_results = sum(
            len(purl_groups[purl]['reachable']) + 
            len(purl_groups[purl]['unreachable']) + 
            len(purl_groups[purl]['unknown']) 
            for purl in purl_groups
        )
        
        panels = []
        findings_shown = 0
        was_truncated = False
        
        # Sort PURLs by highest severity finding (critical first)
        purl_severity_list = []
        for purl in purl_groups:
            min_sev = 999
            for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
                for finding in purl_groups[purl][reach_type]:
                    if finding['severity_rank'] < min_sev:
                        min_sev = finding['severity_rank']
            purl_severity_list.append((min_sev, purl))
        
        purl_severity_list.sort(key=lambda x: x[0])
        
        # Detect language once per PURL
        for _, purl in purl_severity_list:
            if findings_shown >= result_limit:
                was_truncated = True
                break
            
            language = _detect_language_from_purl(purl)
            
            # Add PURL header
            panels.append({
                "type": "heading",
                "attrs": {"level": 2},
                "content": [
                    {"type": "text", "text": "📦 Package: ", "marks": [{"type": "strong"}]},
                    {"type": "text", "text": purl, "marks": [{"type": "code"}]}
                ]
            })
            
            # Reachable findings (highest priority)
            if purl_groups[purl]['reachable']:
                panels.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Reachable", "marks": [{"type": "strong"}]}]
                })
                
                for finding in purl_groups[purl]['reachable']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    
                    jira_priority = {
                        'critical': 'Highest',
                        'high': 'High',
                        'medium': 'Medium',
                        'low': 'Low'
                    }.get(finding['severity'], 'Medium')
                    
                    panel_type = {
                        'Highest': 'error',
                        'High': 'warning',
                        'Medium': 'note',
                        'Low': 'info'
                    }.get(jira_priority, 'note')
                    
                    panel_content = [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": f"🔒 {finding['cve_id']}: ", "marks": [{"type": "strong"}]},
                                {"type": "text", "text": jira_priority}
                            ]
                        }
                    ]
                    
                    if finding['trace_str']:
                        panel_content.append({
                            "type": "codeBlock",
                            "attrs": {"language": language.lower()},
                            "content": [{"type": "text", "text": finding['trace_str']}]
                        })
                    
                    panels.append({
                        "type": "panel",
                        "attrs": {"panelType": panel_type},
                        "content": panel_content
                    })
                    
                    findings_shown += 1
            
            # Unknown reachability findings
            if purl_groups[purl]['unknown'] and findings_shown < result_limit:
                panels.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Unknown", "marks": [{"type": "strong"}]}]
                })
                
                for finding in purl_groups[purl]['unknown']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    
                    jira_priority = {
                        'critical': 'Highest',
                        'high': 'High',
                        'medium': 'Medium',
                        'low': 'Low'
                    }.get(finding['severity'], 'Medium')
                    
                    panels.append({
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"🔒 {finding['cve_id']}: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": jira_priority}
                        ]
                    })
                    
                    findings_shown += 1
            
            # Error reachability findings
            if purl_groups[purl]['error'] and findings_shown < result_limit:
                panels.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Error", "marks": [{"type": "strong"}]}]
                })
                
                for finding in purl_groups[purl]['error']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    
                    jira_priority = {
                        'critical': 'Highest',
                        'high': 'High',
                        'medium': 'Medium',
                        'low': 'Low'
                    }.get(finding['severity'], 'Medium')
                    
                    panels.append({
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"🔒 {finding['cve_id']}: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": jira_priority}
                        ]
                    })
                    
                    findings_shown += 1
            
            # Unreachable findings (lowest priority)
            if purl_groups[purl]['unreachable'] and findings_shown < result_limit:
                panels.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Unreachable", "marks": [{"type": "strong"}]}]
                })
                
                for finding in purl_groups[purl]['unreachable']:
                    if findings_shown >= result_limit:
                        was_truncated = True
                        break
                    
                    jira_priority = {
                        'critical': 'Highest',
                        'high': 'High',
                        'medium': 'Medium',
                        'low': 'Low'
                    }.get(finding['severity'], 'Medium')
                    
                    panels.append({
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"🔒 {finding['cve_id']}: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": jira_priority}
                        ]
                    })
                    
                    findings_shown += 1
            
            # Add divider between packages
            panels.append({"type": "rule"})
        
        # Remove the last rule
        if panels and panels[-1]["type"] == "rule":
            panels.pop()
        
        # Add truncation notice if needed
        if was_truncated:
            panels.extend([
                {
                    "type": "rule"
                },
                {
                    "type": "panel",
                    "attrs": {"panelType": "warning"},
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": f"⚠️ Results truncated to {result_limit} highest severity findings (total: {total_results}). View more in full scan.", "marks": [{"type": "strong"}]}
                            ]
                        }
                    ]
                }
            ])
        
        content = {
            "type": "doc",
            "version": 1,
            "content": panels
        }
    
    return [{
        'title': 'Socket Tier1 Reachability Analysis',
        'content': content
    }]