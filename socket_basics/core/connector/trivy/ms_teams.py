#!/usr/bin/env python3
"""
Microsoft Teams notifier for Trivy results.
Formats results using the new grouped format suitable for Teams.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .utils import get_notifier_result_limit, logger


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image") -> List[Dict[str, Any]]:
    """Format for Microsoft Teams - grouped format.
    
    Args:
        mapping: Component mapping with alerts
        item_name: Name of the scanned item
        scan_type: Type of scan - 'vuln', 'image', or 'dockerfile'
    """
    # Group vulnerabilities by package and severity
    package_groups = defaultdict(lambda: defaultdict(set))  # Use set to avoid duplicates
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    if scan_type == 'dockerfile':
        # Process dockerfile components
        for comp in mapping.values():
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                rule_id = str(props.get('ruleId', '') or alert.get('title', ''))
                severity = str(alert.get('severity', '')).lower()
                message = str(alert.get('description', ''))
                resolution = str(props.get('resolution', ''))
                
                # Count by severity
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                rule_info = f"{rule_id}|{message}|{resolution}"
                package_groups[rule_id][severity].add(rule_info)
                
    else:  # image or vuln
        # Process package vulnerability components
        for comp in mapping.values():
            comp_name = str(comp.get('name') or comp.get('id') or '-')
            comp_version = str(comp.get('version', ''))
            ecosystem = comp.get('qualifiers', {}).get('ecosystem', 'unknown')
            
            if comp_version:
                package_key = f"pkg:{ecosystem}/{comp_name}@{comp_version}"
            else:
                package_key = f"pkg:{ecosystem}/{comp_name}"
            
            for alert in comp.get('alerts', []):
                props = alert.get('props', {}) or {}
                cve_id = str(props.get('vulnerabilityId', '') or alert.get('title', ''))
                severity = str(alert.get('severity', '')).lower()
                
                # Count by severity
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                package_groups[package_key][severity].add(cve_id)
    
    # Create rows with proper formatting
    rows = []
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    if scan_type == 'dockerfile':
        # Dockerfile format: Rule ID | Severity | Message | Resolution
        for rule_id, severity_dict in package_groups.items():
            for severity in sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4)):
                rule_infos = list(severity_dict[severity])
                for rule_info in rule_infos:
                    parts = rule_info.split('|', 2)
                    if len(parts) >= 3:
                        _, message, resolution = parts
                        
                        # Add severity emojis
                        severity_emoji = {
                            'critical': '🔴',
                            'high': '🟠',
                            'medium': '🟡',
                            'low': '⚪'
                        }.get(severity, '⚪')
                        
                        rows.append((
                            severity_order.get(severity, 4),
                            [rule_id, severity_emoji, severity, message, resolution[:150] + '...' if len(resolution) > 150 else resolution]
                        ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
    else:
        # Image format: Package | CVEs | Severity  
        for package_name, severity_dict in package_groups.items():
            # Sort severities by criticality
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))  # Convert set to sorted list
                
                # Format CVEs as compact list for Teams
                if len(cves) > 3:
                    cve_list = ', '.join(cves[:3]) + f', ... (+{len(cves)-3} more)'
                else:
                    cve_list = ', '.join(cves)
                
                # Add severity emojis
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '⚪'
                }.get(severity, '⚪')
                
                # Truncate package name for readability if needed
                display_package = package_name[:40] + '...' if len(package_name) > 40 else package_name
                
                rows.append((
                    severity_order.get(severity, 4),
                    [display_package, cve_list, severity_emoji, severity]
                ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
    
    # Apply truncation for MS Teams
    max_rows = get_notifier_result_limit('msteams')
    original_count = len(rows)
    truncated = False
    if len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True
        logger.info(f"Truncated MS Teams results from {original_count} to {max_rows}")
    
    # Format for MS Teams
    if not rows:
        content = "✅ No vulnerabilities found."
    else:
        # Add summary table
        content_lines = [
            "**Summary**\n\n",
            f"🔴 Critical: {severity_counts['critical']} | 🟠 High: {severity_counts['high']} | 🟡 Medium: {severity_counts['medium']} | ⚪ Low: {severity_counts['low']}\n\n",
            "---\n\n",
            "**Details**\n\n"
        ]
        
        if scan_type == 'dockerfile':
            # Dockerfile format
            for idx, row in enumerate(rows, 1):
                rule_id, severity_emoji, severity, message, resolution = row
                content_lines.append(
                    f"{severity_emoji} **{rule_id}** ({severity.upper()})\n\n"
                    f"**Message:** {message}\n\n"
                    f"**Resolution:** {resolution}\n\n---\n"
                )
        else:
            # Image/CVE format
            for idx, row in enumerate(rows, 1):
                package, cves, severity_emoji, severity = row
                content_lines.append(
                    f"{severity_emoji} **{package}** ({severity.upper()})\n\n"
                    f"**CVEs:** {cves}\n\n---\n"
                )
        
        content = "".join(content_lines)
        
        # Add truncation notice if needed
        if truncated:
            content += f"\n⚠️ **Showing top {max_rows} results (by severity).** {original_count - max_rows} additional results truncated. View more in full scan."
    
    # Create title based on scan type
    if scan_type == 'vuln':
        title = f'Socket Trivy CVE: {item_name}'
    elif scan_type == 'dockerfile':
        title = f'Socket Trivy Dockerfile: {item_name}'
    else:  # image
        title = f'Socket Trivy Image: {item_name}'
    
    return [{
        'title': title,
        'content': content
    }]