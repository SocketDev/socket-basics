#!/usr/bin/env python3
"""
Microsoft Sentinel notifier for Trivy results.
Formats results using the new grouped format structured for SIEM ingestion.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .utils import get_notifier_result_limit, logger


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image") -> List[Dict[str, Any]]:
    """Format for Microsoft Sentinel - grouped format structured for SIEM ingestion.
    
    Args:
        mapping: Component mapping with alerts
        item_name: Name of the scanned item
        scan_type: Type of scan - 'vuln', 'image', or 'dockerfile'
    """
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
                severity = str(alert.get('severity', ''))
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
                        rows.append((
                            severity_order.get(severity, 4),
                            [rule_id, severity, message, resolution]
                        ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        headers = ['Rule ID', 'Severity', 'Message', 'Resolution']
    else:
        # Image format: Package | CVEs | Severity  
        for package_name, severity_dict in package_groups.items():
            # Sort severities by criticality
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))  # Convert set to sorted list
                
                # Format CVEs as list for SIEM parsing
                cve_list = '; '.join(cves)
                
                rows.append((
                    severity_order.get(severity, 4),
                    [package_name, cve_list, severity]
                ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        headers = ['Package', 'CVEs', 'Severity']
    
    # Apply truncation for MS Sentinel
    max_rows = get_notifier_result_limit('ms_sentinel')
    original_count = len(rows)
    truncated = False
    if len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True
        logger.info(f"Truncated MS Sentinel results from {original_count} to {max_rows}")
    
    # Format for MS Sentinel - structured data
    if not rows:
        content = "No vulnerabilities found."
    else:
        content_lines = [' | '.join(headers)]
        content_lines.append(' | '.join(['---'] * len(headers)))
        for row in rows:
            content_lines.append(' | '.join(str(cell) for cell in row))
        
        # Add truncation notice if needed
        if truncated:
            content_lines.append('')
            content_lines.append(f"⚠️ Showing top {max_rows} results (by severity). {original_count - max_rows} additional results truncated. View full results at the scan URL.")
        
        content = '\n'.join(content_lines)
    
    # Create title based on scan type
    if scan_type == 'vuln':
        title = f'Socket CVE Scanning Findings: {item_name}'
    elif scan_type == 'dockerfile':
        title = f'Socket Dockerfile Findings: {item_name}'
    else:  # image
        title = f'Socket Image Scanning Findings: {item_name}'
    
    return [{
        'title': title,
        'content': content
    }]