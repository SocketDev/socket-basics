#!/usr/bin/env python3
"""
Jira notifier for Trivy results.
Formats results using the new grouped format with priority mapping and detailed descriptions.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .utils import get_notifier_result_limit, logger


def format_notifications(mapping: Dict[str, Any], item_name: str = "Unknown", scan_type: str = "image") -> List[Dict[str, Any]]:
    """Format for Jira tickets - grouped format with priority mapping.
    
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
                
                # Check for code snippets or detailed content
                code_snippet = ""
                detailed_report = props.get('detailedReport', {})
                if detailed_report and detailed_report.get('content'):
                    code_snippet = str(detailed_report.get('content', ''))
                
                # Store complete rule info including code snippet
                rule_info = f"{rule_id}|{message}|{resolution}|{code_snippet}"
                package_groups[rule_id][severity].add(rule_info)
                
    elif scan_type == 'image':
        # Process container image vulnerability components
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
                
    elif scan_type == 'vuln':
        # Process filesystem vulnerability components
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
                    parts = rule_info.split('|', 3)
                    if len(parts) >= 3:
                        # parts[0] = rule_id, parts[1] = message, parts[2] = resolution, parts[3] = code_snippet
                        message = parts[1]
                        resolution = parts[2]
                        code_snippet = parts[3] if len(parts) > 3 else ""
                        
                        # Extract code snippets for ADF format
                        code_content = None
                        if code_snippet and code_snippet.strip():
                            # Extract actual code from markdown if present
                            if '```' in code_snippet:
                                import re
                                code_matches = re.findall(r'```[\w]*\n?(.*?)\n?```', code_snippet, re.DOTALL)
                                if code_matches:
                                    actual_code = code_matches[0].strip()
                                    # Create ADF code block for Dockerfile
                                    code_content = {
                                        "type": "codeBlock",
                                        "attrs": {"language": "dockerfile"},
                                        "content": [{"type": "text", "text": actual_code}]
                                    }
                        
                        # Map severity to Jira priority
                        severity_lower = severity.lower()
                        jira_priority = {
                            'critical': 'Highest',
                            'high': 'High',
                            'medium': 'Medium', 
                            'low': 'Low'
                        }.get(severity_lower, 'Medium')
                        
                        # Create message content with optional code block
                        message_content = [{"type": "paragraph", "content": [{"type": "text", "text": message}]}]
                        if code_content:
                            message_content.append(code_content)
                        
                        rows.append([
                            {"type": "paragraph", "content": [{"type": "text", "text": rule_id}]},
                            {"type": "paragraph", "content": [{"type": "text", "text": jira_priority}]},
                            {"type": "div", "content": message_content},
                            {"type": "paragraph", "content": [{"type": "text", "text": resolution}]}
                        ])
        
        headers = ['Rule ID', 'Priority', 'Message', 'Resolution']
        
    elif scan_type == 'image':
        # Container image format: Package | CVEs | Priority
        for package_name, severity_dict in package_groups.items():
            # Sort severities by criticality
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))  # Convert set to sorted list
                
                # Format CVEs as compact list for Jira (limit content length)
                if len(cves) > 10:
                    # Truncate to avoid content limits
                    cve_list = ', '.join(cves[:10]) + f' ... (+{len(cves)-10} more)'
                else:
                    cve_list = ', '.join(cves)
                
                # Map severity to Jira priority
                severity_lower = severity.lower()
                jira_priority = {
                    'critical': 'Highest',
                    'high': 'High',
                    'medium': 'Medium', 
                    'low': 'Low'
                }.get(severity_lower, 'Medium')
                
                # Truncate package name if too long
                display_package = package_name[:80] + '...' if len(package_name) > 80 else package_name
                
                rows.append([
                    {"type": "paragraph", "content": [{"type": "text", "text": display_package}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": cve_list}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": jira_priority}]}
                ])
        
        headers = ['Package', 'CVEs', 'Priority']
        
    elif scan_type == 'vuln':
        # Filesystem vulnerability format: Package | CVEs | Priority
        for package_name, severity_dict in package_groups.items():
            # Sort severities by criticality
            sorted_severities = sorted(severity_dict.keys(), key=lambda s: severity_order.get(s, 4))
            
            for severity in sorted_severities:
                cves = sorted(list(severity_dict[severity]))  # Convert set to sorted list
                
                # Format CVEs as compact list for Jira (limit content length)
                if len(cves) > 10:
                    # Truncate to avoid content limits
                    cve_list = ', '.join(cves[:10]) + f' ... (+{len(cves)-10} more)'
                else:
                    cve_list = ', '.join(cves)
                
                # Map severity to Jira priority
                severity_lower = severity.lower()
                jira_priority = {
                    'critical': 'Highest',
                    'high': 'High',
                    'medium': 'Medium', 
                    'low': 'Low'
                }.get(severity_lower, 'Medium')
                
                # Truncate package name if too long
                display_package = package_name[:80] + '...' if len(package_name) > 80 else package_name
                
                rows.append([
                    {"type": "paragraph", "content": [{"type": "text", "text": display_package}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": cve_list}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": jira_priority}]}
                ])
        
        headers = ['Package', 'CVEs', 'Priority']
    
    # Create ADF content
    if not rows:
        content = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "No vulnerabilities found."}]
                }
            ]
        }
    else:
        # Get Jira-specific result limit from config
        max_items = get_notifier_result_limit('jira')
        
        # Sort rows by severity (highest first) before truncating
        def get_row_severity_order(row):
            try:
                if scan_type == 'dockerfile':
                    priority_text = row[1].get('content', [{}])[0].get('text', 'Medium')
                else:
                    priority_text = row[2].get('content', [{}])[0].get('text', 'Medium')
                priority_to_order = {'Highest': 0, 'High': 1, 'Medium': 2, 'Low': 3}
                return priority_to_order.get(priority_text, 4)
            except Exception:
                return 4

        sorted_rows = sorted(rows, key=get_row_severity_order)
        display_rows = sorted_rows[:max_items] if len(sorted_rows) > max_items else sorted_rows
        truncated_count = len(rows) - len(display_rows)

        # Build panels for image and vuln scan types
        panels = []
        if scan_type in ('image', 'vuln'):
            # Each row corresponds to [Package, CVEs, Priority]
            for row in display_rows:
                try:
                    pkg_cell = row[0]
                    cves_cell = row[1]
                    priority_cell = row[2]
                    pkg_text = pkg_cell.get('content', [{}])[0].get('text', '-') if isinstance(pkg_cell, dict) else str(pkg_cell)
                    cves_text = cves_cell.get('content', [{}])[0].get('text', '-') if isinstance(cves_cell, dict) else str(cves_cell)
                    priority_text = priority_cell.get('content', [{}])[0].get('text', 'Medium') if isinstance(priority_cell, dict) else str(priority_cell)
                except Exception:
                    pkg_text = str(row[0]) if len(row) > 0 else '-'
                    cves_text = str(row[1]) if len(row) > 1 else '-'
                    priority_text = str(row[2]) if len(row) > 2 else 'Medium'

                # Build panel content similar to Tier1
                panel_type = 'warning' if priority_text in ('High', 'Highest') else 'info'
                panel_content = [
                    {"type": "paragraph", "content": [{"type": "text", "text": f"Package Vulnerability: {cves_text.split(',')[0].strip()}", "marks": [{"type": "strong"}]}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": "Vulnerability Details", "marks": [{"type": "strong"}]}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": "• CVE ID: "}, {"type": "text", "text": cves_text.split(',')[0].strip()}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": "• Package: "}, {"type": "text", "text": pkg_text, "marks": [{"type": "code"}]}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": "• Severity: "}, {"type": "text", "text": priority_text}]}
                ]

                # Optional description/recommendation extraction not available from compact rows
                # Add panel and a rule separator
                panels.append({"type": "panel", "attrs": {"panelType": panel_type}, "content": panel_content})
                panels.append({"type": "rule"})

            # Remove trailing rule
            if panels and panels[-1].get('type') == 'rule':
                panels.pop()

            # Add truncation panel if needed
            if truncated_count > 0:
                truncation_panel = {
                    "type": "panel",
                    "attrs": {"panelType": "info"},
                    "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": "⚠️ ", "marks": [{"type": "strong"}]}, {"type": "text", "text": f"Showing top {max_items} results (by severity). "}, {"type": "text", "text": f"{truncated_count} additional results truncated. View full results at the scan URL."} ]}
                    ]
                }
                panels.append(truncation_panel)

            content = {"type": "doc", "version": 1, "content": panels}

        else:
            # Keep original table behavior for dockerfile
            # Rebuild table rows from display_rows
            header_cells = []
            for header in headers:
                header_cells.append({
                    "type": "tableHeader",
                    "attrs": {},
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": header}]}]
                })

            table_rows = [{"type": "tableRow", "content": header_cells}]
            for row in display_rows:
                data_cells = []
                for cell_content in row:
                    data_cells.append({
                        "type": "tableCell",
                        "attrs": {},
                        "content": [cell_content] if isinstance(cell_content, dict) else [{"type": "paragraph", "content": [{"type": "text", "text": str(cell_content)}]}]
                    })
                table_rows.append({"type": "tableRow", "content": data_cells})

            content = {"type": "doc", "version": 1, "content": [{"type": "table", "attrs": {"isNumberColumnEnabled": False, "layout": "default"}, "content": table_rows}]}
    
    # Create title based on scan type
    if scan_type == 'vuln':
        title = f'Trivy Vuln Scanning Results: {item_name}'
    elif scan_type == 'dockerfile':
        title = f'Trivy Dockerfile Results: {item_name}'
    else:  # image
        title = f'Trivy Container Results: {item_name}'
    
    return [{
        'title': title,
        'content': content
    }]