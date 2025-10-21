#!/usr/bin/env python3
"""
Jira notifier for TruffleHog results.
Formats results for Jira tickets with priority mapping and detailed descriptions for secret detection.
"""

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


def format_notifications(mapping: Dict[str, Any], config=None) -> List[Dict[str, Any]]:
    """Format for Jira tickets - generate ADF format directly for proper formatting."""
    findings = []
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    for comp in mapping.values():
        for a in comp.get('alerts', []):
            props = a.get('props', {}) or {}
            detector = str(props.get('detectorName', '') or a.get('title') or '')
            severity = str(a.get('severity', '')).lower()
            file_path = str(props.get('filePath', ''))
            line = str(props.get('lineNumber', ''))
            verified = props.get('verified', False)
            
            # Map severity to Jira priority
            jira_priority = {
                'critical': 'Highest',
                'high': 'High',
                'medium': 'Medium', 
                'low': 'Low'
            }.get(severity, 'Medium')
            
            # Enhanced priority for verified secrets
            if verified and jira_priority != 'Highest':
                jira_priority = 'High'
            
            # Risk assessment
            risk_level = 'CRITICAL' if verified else 'Medium'
            
            # Action needed
            action = 'URGENT: Rotate credentials immediately' if verified else 'Review and validate'
            
            location = f"{file_path}:{line}" if line else file_path
            
            findings.append((
                severity_order.get(severity, 4),
                [
                    {"type": "paragraph", "content": [{"type": "text", "text": detector}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": jira_priority}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": 'Verified' if verified else 'Unverified'}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": risk_level}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": location}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": action}]},
                    {"type": "paragraph", "content": [{"type": "text", "text": str(a.get('description', ''))}]}
                ]
            ))
    
    # Sort by severity
    findings.sort(key=lambda x: x[0])
    rows = [f[1] for f in findings]
    
    # Apply truncation
    result_limit = _get_jira_result_limit()
    total_results = len(rows)
    was_truncated = False
    
    if total_results > result_limit:
        logger.info(f"Truncating Jira TruffleHog results from {total_results} to {result_limit} (prioritized by severity)")
        rows = rows[:result_limit]
        was_truncated = True
    
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
        
        # Build content
        doc_content = [
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
        
        # Add truncation notice if needed
        if was_truncated:
            doc_content.extend([
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
        
        # Create complete ADF document
        content = {
            "type": "doc",
            "version": 1,
            "content": doc_content
        }
    
    return [{
        'title': title,
        'content': content
    }]