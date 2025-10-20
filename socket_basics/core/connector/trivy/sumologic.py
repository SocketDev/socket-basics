#!/usr/bin/env python3
"""
SumoLogic notifier for Trivy results.
Formats results using the new grouped format in structured logging format suitable for log parsing.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .utils import get_notifier_result_limit, logger


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image") -> List[Dict[str, Any]]:
    """Format for Sumo Logic - grouped format structured for log analysis.
    
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
                        # Key-value format for SumoLogic
                        rows.append((
                            severity_order.get(severity, 4),
                            [f"rule_id={rule_id}", f"severity={severity}", f"message={message}", 
                             f"resolution={resolution}", "scanner=trivy", "type=dockerfile"]
                        ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        # No headers needed for log format
        headers = []
    else:
        # Image format: Package | CVEs | Severity  
        for package_name, severity_dict in package_groups.items():
            # Sort severities by criticality
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))  # Convert set to sorted list
                
                # Format CVEs as comma-separated for log parsing
                cve_list = ','.join(cves)
                
                # Key-value format for SumoLogic
                rows.append((
                    severity_order.get(severity, 4),
                    [f"package={package_name}", f"cves={cve_list}", f"severity={severity}", 
                     "scanner=trivy", "type=container-image"]
                ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        # No headers needed for log format
        headers = []
    
    # Apply truncation
    result_limit = get_notifier_result_limit('sumologic')
    total_results = len(rows)
    was_truncated = False
    
    if total_results > result_limit:
        logger.info(f"Truncating SumoLogic results from {total_results} to {result_limit} (prioritized by severity)")
        rows = rows[:result_limit]
        was_truncated = True
    
    # Format for SumoLogic - key=value pairs, one per line
    if not rows:
        content = "No vulnerabilities found."
    else:
        content_lines = []
        for row in rows:
            content_lines.append(' '.join(str(cell) for cell in row))
        
        # Add truncation notice if needed
        if was_truncated:
            content_lines.append('')
            content_lines.append(f"results_truncated=true total_results={total_results} displayed_results={result_limit} note=\"Results truncated to {result_limit} highest severity findings. See full scan URL for complete results.\"")
        
        content = '\n'.join(content_lines)
    
    # Create title based on scan type
    if scan_type == 'vuln':
        title = f'Socket CVE Scanning Events: {item_name}'
    elif scan_type == 'dockerfile':
        title = f'Socket Dockerfile Events: {item_name}'
    else:  # image
        title = f'Socket Image Scanning Events: {item_name}'
    
    return [{
        'title': title,
        'content': content
    }]