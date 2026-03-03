"""GitHub PR notifier formatting for Socket Tier1 reachability analysis."""

import re
from typing import Dict, Any, List
from socket_basics.core.notification import github_pr_helpers as helpers


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

    # Get feature flags from config (using shared helper)
    flags = helpers.get_feature_flags(config)
    enable_links = flags['enable_links']
    enable_collapse = flags['enable_collapse']
    collapse_non_critical = flags['collapse_non_critical']
    enable_code_fencing = flags['enable_code_fencing']
    show_rule_names = flags['show_rule_names']
    repository = flags['repository']
    commit_hash = flags['commit_hash']
    full_scan_url = flags['full_scan_url']

    # Use shared severity constants
    severity_order = helpers.SEVERITY_ORDER
    severity_emoji = helpers.SEVERITY_EMOJI
    
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

            # Get CVSS score if available
            cvss_score = None
            if 'cvssScore' in props:
                try:
                    cvss_score = float(props['cvssScore'])
                except (ValueError, TypeError):
                    pass

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
                'rule_name': a.get('title') or cve_id,
                'cvss_score': cvss_score
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
                    # Use new vulnerability header format with CVE link and CVSS score
                    header = helpers.format_vulnerability_header(
                        finding['cve_id'],
                        finding['severity'],
                        finding.get('cvss_score')
                    )
                    content_lines.append(header)

                    # Add rule name if enabled and different from CVE ID
                    if show_rule_names:
                        rule_name = finding.get('rule_name', '')
                        if rule_name and rule_name != finding['cve_id']:
                            content_lines.append(f"**Rule**: `{rule_name}`")

                    if finding['trace']:
                        trace_str = finding['trace']

                        # Add clickable links
                        if enable_links and repository and commit_hash:
                            trace_lines = trace_str.split('\n')
                            trace_str = helpers.format_trace_with_links(
                                trace_lines, repository, commit_hash, enable_links
                            )

                        # Language-aware code fencing
                        lang = ''
                        if enable_code_fencing:
                            # Detect from first filename in trace
                            first_line = trace_str.split('\n')[0] if trace_str else ''
                            match = re.search(r'([^\s]+\.[\w]+)', first_line)
                            if match:
                                lang = helpers.detect_language_from_filename(match.group(1))

                        content_lines.append(f"```{lang}")
                        content_lines.append(trace_str)
                        content_lines.append("```")
                    content_lines.append("")
            
            # Unknown reachability findings
            if purl_groups[purl]['unknown']:
                content_lines.append("**Unknown**")
                content_lines.append("")
                for finding in purl_groups[purl]['unknown']:
                    # Use new vulnerability header format
                    header = helpers.format_vulnerability_header(
                        finding['cve_id'],
                        finding['severity'],
                        finding.get('cvss_score')
                    )
                    content_lines.append(header)

                    # Add rule name if enabled and different from CVE ID
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
                    # Use new vulnerability header format
                    header = helpers.format_vulnerability_header(
                        finding['cve_id'],
                        finding['severity'],
                        finding.get('cvss_score')
                    )
                    content_lines.append(header)

                    # Add rule name if enabled and different from CVE ID
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
                    # Use new vulnerability header format
                    header = helpers.format_vulnerability_header(
                        finding['cve_id'],
                        finding['severity'],
                        finding.get('cvss_score')
                    )
                    content_lines.append(header)

                    # Add rule name if enabled and different from CVE ID
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
    
    # Build title - just scanner name (repo/branch context already visible in PR)
    title = "Socket Security Tier 1"

    # Count total findings
    total_findings = sum(severity_counts.values())

    # Content already includes summary and details sections
    summary_content = content

    # Wrap in standard PR comment section
    wrapped_content = helpers.wrap_pr_comment_section(
        'socket-tier1', title, summary_content, full_scan_url
    )
    
    return [{
        'title': title,
        'content': wrapped_content
    }]