"""GitHub PR notifier formatting for Socket Tier1 reachability analysis."""

import re
from typing import Dict, Any, List
from . import github_helpers


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

    # Get feature flags from config
    enable_links = config.get('pr_comment_links_enabled', True) if config else True
    enable_collapse = config.get('pr_comment_collapse_enabled', True) if config else True
    collapse_non_critical = config.get('pr_comment_collapse_non_critical', True) if config else True
    enable_code_fencing = config.get('pr_comment_code_fencing_enabled', True) if config else True
    show_rule_names = config.get('pr_comment_show_rule_names', True) if config else True

    # Get GitHub metadata for links
    repository = config.repo if config else ''
    commit_hash = config.commit_hash if config else ''
    full_scan_url = config.get('full_scan_html_url') if config else None

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
                'trace': trace_str,
                'rule_name': a.get('title') or cve_id  # Add rule name
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
        
        for min_sev, purl in purl_severity_list:
            # Calculate severity summary for this PURL
            purl_severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for reach_type in ['reachable', 'unknown', 'error', 'unreachable']:
                for finding in purl_groups[purl][reach_type]:
                    sev = finding['severity']
                    if sev in purl_severities:
                        purl_severities[sev] += 1

            # Determine if this section should be auto-expanded
            has_critical = purl_severities['critical'] > 0

            if enable_collapse:
                # Build severity summary for section header
                severity_parts = []
                if purl_severities['critical'] > 0:
                    severity_parts.append(f"{severity_emoji['critical']} Critical: {purl_severities['critical']}")
                if purl_severities['high'] > 0:
                    severity_parts.append(f"{severity_emoji['high']} High: {purl_severities['high']}")
                if purl_severities['medium'] > 0:
                    severity_parts.append(f"{severity_emoji['medium']} Medium: {purl_severities['medium']}")
                if purl_severities['low'] > 0:
                    severity_parts.append(f"{severity_emoji['low']} Low: {purl_severities['low']}")

                severity_summary = " | ".join(severity_parts) if severity_parts else "No issues"

                open_attr = ' open' if (not collapse_non_critical or has_critical) else ''
                content_lines.append(f"<details{open_attr}>")
                content_lines.append(f"<summary><strong>{purl}</strong> ({severity_summary})</summary>")
                content_lines.append("")
            else:
                content_lines.append(f"#### `{purl}`")
                content_lines.append("")

            # Reachable findings (highest priority)
            if purl_groups[purl]['reachable']:
                content_lines.append("**Reachable**")
                content_lines.append("")
                for finding in purl_groups[purl]['reachable']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")

                    # Add rule name if enabled
                    if show_rule_names:
                        rule_name = finding.get('rule_name', '')
                        if rule_name and rule_name != finding['cve_id']:
                            content_lines.append(f"**Rule**: `{rule_name}`")

                    if finding['trace']:
                        trace_str = finding['trace']

                        # Add clickable links
                        if enable_links and repository and commit_hash:
                            trace_lines = trace_str.split('\n')
                            trace_str = github_helpers.format_trace_with_links(
                                trace_lines, repository, commit_hash, enable_links
                            )

                        # Language-aware code fencing
                        lang = ''
                        if enable_code_fencing:
                            # Detect from first filename in trace
                            first_line = trace_str.split('\n')[0] if trace_str else ''
                            match = re.search(r'([^\s]+\.[\w]+)', first_line)
                            if match:
                                lang = github_helpers.detect_language_from_filename(match.group(1))

                        content_lines.append(f"```{lang}")
                        content_lines.append(trace_str)
                        content_lines.append("```")
                    content_lines.append("")
            
            # Unknown reachability findings
            if purl_groups[purl]['unknown']:
                content_lines.append("**Unknown**")
                content_lines.append("")
                for finding in purl_groups[purl]['unknown']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")

                    # Add rule name if enabled
                    if show_rule_names:
                        rule_name = finding.get('rule_name', '')
                        if rule_name and rule_name != finding['cve_id']:
                            content_lines.append(f"**Rule**: `{rule_name}`")
                content_lines.append("")

            # Error reachability findings
            if purl_groups[purl]['error']:
                content_lines.append("**Error**")
                content_lines.append("")
                for finding in purl_groups[purl]['error']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")

                    # Add rule name if enabled
                    if show_rule_names:
                        rule_name = finding.get('rule_name', '')
                        if rule_name and rule_name != finding['cve_id']:
                            content_lines.append(f"**Rule**: `{rule_name}`")
                content_lines.append("")

            # Unreachable findings (lowest priority)
            if purl_groups[purl]['unreachable']:
                content_lines.append("**Unreachable**")
                content_lines.append("")
                for finding in purl_groups[purl]['unreachable']:
                    emoji = severity_emoji.get(finding['severity'], '⚪')
                    content_lines.append(f"{emoji} **{finding['cve_id']}**: *{finding['severity'].upper()}*")

                    # Add rule name if enabled
                    if show_rule_names:
                        rule_name = finding.get('rule_name', '')
                        if rule_name and rule_name != finding['cve_id']:
                            content_lines.append(f"**Rule**: `{rule_name}`")
                content_lines.append("")

            # Close collapsible section
            if enable_collapse:
                content_lines.append("</details>")
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

    # Add full scan link at top if available
    scan_link_section = ''
    if full_scan_url:
        scan_link_section = f"\n\n🔗 **[View Full Socket Scan Report]({full_scan_url})**\n\n---\n"

    # Wrap content with HTML comment markers for section updates
    wrapped_content = f"""<!-- socket-tier1 start -->
# {title}
{scan_link_section}
{summary_content}
<!-- socket-tier1 end -->"""
    
    return [{
        'title': title,
        'content': wrapped_content
    }]