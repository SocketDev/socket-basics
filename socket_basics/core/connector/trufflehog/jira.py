#!/usr/bin/env python3
"""
Jira notifier for TruffleHog results.
Formats results for Jira tickets with priority mapping and detailed descriptions for secret detection.
"""

from typing import Dict, Any, List


def format_notifications(mapping: Dict[str, Any], config=None) -> List[Dict[str, Any]]:
    """Format for Jira tickets - generate ADF format directly for proper formatting."""
    rows = []
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', ''))
            file_path = str(props.get('filePath', ''))
            line = str(props.get('lineNumber', ''))
            verified = props.get('verified', False)
            
            # Map severity to Jira priority
            severity_lower = severity.lower()
            jira_priority = {
                'critical': 'Highest',
                'high': 'High',
                'medium': 'Medium', 
                'low': 'Low'
            }.get(severity_lower, 'Medium')
            
            # Enhanced priority for verified secrets
            if verified and jira_priority != 'Highest':
                jira_priority = 'High'
            
            # Risk assessment
            risk_level = 'CRITICAL' if verified else 'Medium'
            
            # Action needed
            action = 'URGENT: Rotate credentials immediately' if verified else 'Review and validate'
            
            location = f"{file_path}:{line}" if line else file_path
            
            rows.append([
                {"type": "paragraph", "content": [{"type": "text", "text": detector}]},
                {"type": "paragraph", "content": [{"type": "text", "text": jira_priority}]},
                {"type": "paragraph", "content": [{"type": "text", "text": 'Verified' if verified else 'Unverified'}]},
                {"type": "paragraph", "content": [{"type": "text", "text": risk_level}]},
                {"type": "paragraph", "content": [{"type": "text", "text": location}]},
                {"type": "paragraph", "content": [{"type": "text", "text": action}]},
                {"type": "paragraph", "content": [{"type": "text", "text": str(a.get('description', ''))}]}
            ])
    
    # Build simple title with repo/branch/commit info from config
    title_parts = ["Socket Security Issues found for"]
    if config:
        if config.repo:
            title_parts.append(config.repo)
        if config.branch:
            title_parts.append(config.branch)
        if config.commit_hash:
            title_parts.append(config.commit_hash)
    
    title = " - ".join(title_parts)
    
    # Create ADF table format
    if not rows:
        content = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 2},
                    "content": [{"type": "text", "text": "TruffleHog Secret Detection"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "No secrets detected."}]
                }
            ]
        }
    else:
        # Create table headers
        headers = ['Detector', 'Priority', 'Status', 'Risk', 'Location', 'Action', 'Description']
        header_cells = []
        for header in headers:
            header_cells.append({
                "type": "tableHeader",
                "attrs": {},
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": header}]
                    }
                ]
            })
        
        # Create table rows
        table_rows = [{
            "type": "tableRow",
            "content": header_cells
        }]
        
        for row in rows:
            data_cells = []
            for cell_content in row:
                data_cells.append({
                    "type": "tableCell",
                    "attrs": {},
                    "content": [cell_content]
                })
            table_rows.append({
                "type": "tableRow",
                "content": data_cells
            })
        
        # Create complete ADF document
        content = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 2},
                    "content": [{"type": "text", "text": "TruffleHog Secret Detection"}]
                },
                {
                    "type": "table",
                    "attrs": {
                        "isNumberColumnEnabled": False,
                        "layout": "default"
                    },
                    "content": table_rows
                }
            ]
        }
    
    return [{
        'title': title,
        'content': content
    }]