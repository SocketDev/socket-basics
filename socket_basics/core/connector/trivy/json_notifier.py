#!/usr/bin/env python3
"""
JSON notifier for Trivy results.
Formats results using the new grouped format with complete structured data for programmatic consumption.
"""

from typing import Dict, Any, List
from collections import defaultdict
import json


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image") -> List[Dict[str, Any]]:
    """Format for JSON output - grouped format with complete structured data.
    
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
    
    # Create structured data with proper formatting
    structured_data = []
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
                        structured_data.append({
                            'rule_id': rule_id,
                            'severity': severity,
                            'message': message,
                            'resolution': resolution,
                            'type': 'dockerfile'
                        })
        format_type = 'dockerfile'
        
    elif scan_type == 'image':
        # Image format: Package | CVEs | Severity  
        for package_name, severity_dict in package_groups.items():
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))
                
                structured_data.append({
                    'package': package_name,
                    'cves': cves,
                    'severity': severity,
                    'type': 'container-image',
                    'cve_count': len(cves)
                })
        format_type = 'container-image'
        
    elif scan_type == 'vuln':
        # Vuln format: Package | CVEs | Severity  
        for package_name, severity_dict in package_groups.items():
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))
                
                structured_data.append({
                    'package': package_name,
                    'cves': cves,
                    'severity': severity,
                    'type': 'vulnerability-scan',
                    'cve_count': len(cves)
                })
        format_type = 'vulnerability-scan'
        
    else:
        structured_data = []
        format_type = 'unknown'
    
    # Format as JSON for structured output
    content = json.dumps({
        'results': structured_data,
        'metadata': {
            'item_name': item_name,
            'total_groups': len(structured_data),
            'format_type': format_type,
            'scan_type': scan_type
        }
    }, indent=2)
    
    # Create title based on scan type
    if scan_type == 'vuln':
        title = f'Socket CVE Scanning Results: {item_name}'
    elif scan_type == 'dockerfile':
        title = f'Socket Dockerfile Results: {item_name}'
    else:  # image
        title = f'Socket Image Scanning Results: {item_name}'
    
    return [{
        'title': title,
        'content': content
    }]