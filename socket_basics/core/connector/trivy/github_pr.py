#!/usr/bin/env python3
"""
GitHub PR notifier for Trivy results.
Formats results with markdown for better GitHub display using the new grouped format.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .utils import logger, get_notifier_result_limit
from socket_basics.core.notification import github_pr_helpers as helpers


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image", config=None) -> List[Dict[str, Any]]:
    """Format for GitHub PR comments - grouped format with markdown formatting.

    Args:
        mapping: Component mapping with alerts
        item_name: Name of the scanned item
        scan_type: Type of scan - 'vuln', 'image', or 'dockerfile'
        config: Optional configuration object with feature flags
    """
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

    # Group vulnerabilities by package and severity
    package_groups = defaultdict(lambda: defaultdict(set))  # Use set to avoid duplicates
    
    if scan_type == 'dockerfile':
        # Process dockerfile components
        for comp in mapping.values():
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                rule_id = str(props.get('ruleId', '') or alert.get('title', ''))
                severity = str(alert.get('severity', ''))
                message = str(alert.get('description', ''))
                resolution = str(props.get('resolution', ''))
                
                # Check for code snippets or detailed content
                code_snippet = ""
                detailed_report = props.get('detailedReport', {})
                if detailed_report and detailed_report.get('content'):
                    code_snippet = str(detailed_report.get('content', ''))
                
                # For dockerfile, store complete rule info including code snippet
                rule_info = f"{rule_id}|{message}|{resolution}|{code_snippet}"
                package_groups[rule_id][severity].add(rule_info)
                
    else:  # image or vuln
        # Process package vulnerability components
        for comp in mapping.values():
            comp_name = str(comp.get('name') or comp.get('id') or '-')
            comp_version = str(comp.get('version', ''))
            ecosystem = comp.get('qualifiers', {}).get('ecosystem', 'unknown')
            
            # Create purl format: pkg:ecosystem/name@version
            if comp_version:
                package_key = f"pkg:{ecosystem}/{comp_name}@{comp_version}"
            else:
                package_key = f"pkg:{ecosystem}/{comp_name}"
            
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                cve_id = str(props.get('vulnerabilityId', ''))
                severity = str(alert.get('severity', ''))
                
                # Group CVEs by package and severity, use set to avoid duplicates
                package_groups[package_key][severity].add(cve_id)
    
    # Create rows with proper formatting
    rows = []
    severity_order = helpers.SEVERITY_ORDER
    severity_emoji = helpers.SEVERITY_EMOJI

    if scan_type == 'dockerfile':
        # Dockerfile format: Rule ID | Severity | Message | Resolution
        # Collect and sort by severity first
        unsorted_rows = []
        for rule_id, severity_dict in package_groups.items():
            for severity in sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4)):
                rule_infos = list(severity_dict[severity])
                for rule_info in rule_infos:
                    parts = rule_info.split('|', 3)
                    if len(parts) >= 3:
                        # parts[0] = rule_id, parts[1] = message, parts[2] = resolution, parts[3] = code_snippet
                        message = parts[1]
                        resolution = parts[2] 
                        code_snippet = parts[3] if len(parts) > 3 else ""
                        
                        # Format code snippets for GitHub PR comments
                        if code_snippet and code_snippet.strip():
                            # Extract actual code from markdown if present
                            if '```' in code_snippet:
                                # Extract code between markdown code blocks
                                import re
                                code_matches = re.findall(r'```[\w]*\n?(.*?)\n?```', code_snippet, re.DOTALL)
                                if code_matches:
                                    actual_code = code_matches[0].strip()
                                    # Format with <pre> tags and <br> for line breaks
                                    formatted_code = f"<pre>{actual_code.replace(chr(10), '<br>')}</pre>"
                                    message = f"{message}<br><br>{formatted_code}"
                        
                        unsorted_rows.append((
                            severity_order.get(severity, 4),
                            [f"**{rule_id}**", f"*{severity}*", message, resolution]
                        ))
        
        # Sort by severity and extract rows
        unsorted_rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in unsorted_rows]
        
        headers = ['Rule ID', 'Severity', 'Message', 'Resolution']
        
    elif scan_type == 'image':
        # Image format: Expandable panels for each CVE
        # Store full alert details from original mapping for panels
        vuln_details = []
        for comp in mapping.values():
            comp_name = str(comp.get('name') or comp.get('id') or '-')
            comp_version = str(comp.get('version', ''))
            ecosystem = comp.get('qualifiers', {}).get('ecosystem', 'unknown')
            
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                cve_id = str(props.get('vulnerabilityId', ''))
                severity = str(alert.get('severity', '')).lower()
                description = str(alert.get('description', 'No description available'))
                
                # Build package identifier
                if comp_version:
                    package = f"pkg:{ecosystem}/{comp_name}@{comp_version}"
                else:
                    package = f"pkg:{ecosystem}/{comp_name}"
                
                # Get additional metadata
                fixed_version = str(props.get('fixedVersion', 'Not available'))
                installed_version = comp_version or 'Unknown'
                
                vuln_details.append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'severity_order': severity_order.get(severity, 4),
                    'package': package,
                    'comp_name': comp_name,
                    'ecosystem': ecosystem,
                    'installed_version': installed_version,
                    'fixed_version': fixed_version,
                    'description': description
                })
        
        # Sort by severity
        vuln_details.sort(key=lambda x: x['severity_order'])
        rows = vuln_details  # Store for panel rendering
        headers = []  # No table headers for panel format
        
    elif scan_type == 'vuln':
        # Vuln format: Expandable panels for each CVE
        # Store full alert details from original mapping for panels
        vuln_details = []
        for comp in mapping.values():
            comp_name = str(comp.get('name') or comp.get('id') or '-')
            comp_version = str(comp.get('version', ''))
            ecosystem = comp.get('qualifiers', {}).get('ecosystem', 'unknown')
            
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                cve_id = str(props.get('vulnerabilityId', ''))
                severity = str(alert.get('severity', '')).lower()
                description = str(alert.get('description', 'No description available'))
                
                # Build package identifier
                if comp_version:
                    package = f"pkg:{ecosystem}/{comp_name}@{comp_version}"
                else:
                    package = f"pkg:{ecosystem}/{comp_name}"
                
                # Get additional metadata
                fixed_version = str(props.get('fixedVersion', 'Not available'))
                installed_version = comp_version or 'Unknown'
                
                vuln_details.append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'severity_order': severity_order.get(severity, 4),
                    'package': package,
                    'comp_name': comp_name,
                    'ecosystem': ecosystem,
                    'installed_version': installed_version,
                    'fixed_version': fixed_version,
                    'description': description
                })
        
        # Sort by severity
        vuln_details.sort(key=lambda x: x['severity_order'])
        rows = vuln_details  # Store for panel rendering
        headers = []  # No table headers for panel format
        
    else:
        rows = []
        headers = []
    
    # Apply truncation for GitHub PR
    max_rows = get_notifier_result_limit('github_pr')
    original_count = len(rows)
    truncated = False
    if len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True
        logger.info(f"Truncated GitHub PR results from {original_count} to {max_rows}")
    
    # Format content based on scan_type
    if not rows:
        content = "No vulnerabilities found."
    elif scan_type in ['image', 'vuln']:
        # Panel format for vulnerability scanning
        panels = []
        for vuln in rows:
            # Use shared severity emoji
            icon = severity_emoji.get(vuln['severity'], '⚪')
            severity_label = vuln['severity'].upper()
            
            # Create expandable panel for each CVE
            panel = f"""<details>
<summary>{icon} <b>{vuln['cve_id']}</b></summary>

**Severity:** {severity_label}

**Package:** `{vuln['package']}`

**Installed Version:** {vuln['installed_version']}

**Fixed Version:** {vuln['fixed_version']}

**Ecosystem:** {vuln['ecosystem']}

### Description
{vuln['description']}

</details>

"""
            panels.append(panel)
        
        content = '\n'.join(panels)
        
        # Add truncation notice if needed
        if truncated:
            content += f"\n> ⚠️ **Showing top {max_rows} results (by severity).** {original_count - max_rows} additional results truncated.\n"
            
    else:
        # Table format for dockerfile scanning
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        content_rows = []
        for row in rows:
            content_rows.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
        
        content = '\n'.join([header_row, separator_row] + content_rows)
        
        # Add truncation notice if needed
        if truncated:
            content += f"\n\n> ⚠️ **Showing top {max_rows} results (by severity).** {original_count - max_rows} additional results truncated.\n"
    
    # Build title based on scan type
    if scan_type == 'vuln':
        title_base = "Socket CVE Scanning Results"
        scanner_name = "Trivy Vuln Scanning"
    elif scan_type == 'dockerfile':
        title_base = "Socket Dockerfile Results"
        scanner_name = "Trivy Dockerfile"
    else:  # image
        title_base = "Socket Image Scanning Results"
        scanner_name = "Trivy Container"
    
    title = f"{title_base}: {item_name}"

    # Count total findings for summary
    total_findings = len(rows)

    # Add summary section with scanner findings
    summary_content = f"""## Summary

| Scanner | Findings |
|---------|----------|
| {scanner_name} | {total_findings} |

## Details

{content}"""

    # Add full scan link at top if available (using shared helper)
    scan_link_section = helpers.format_scan_link_section(full_scan_url)

    # Wrap content with HTML comment markers for section updates
    wrapped_content = f"""<!-- trivy-container start -->
# {title}
{scan_link_section}
{summary_content}
<!-- trivy-container end -->"""
    
    return [{
        'title': title,
        'content': wrapped_content
    }]