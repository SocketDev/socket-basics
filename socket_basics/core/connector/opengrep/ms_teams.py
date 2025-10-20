#!/usr/bin/env python3
"""
Microsoft Teams notifier for OpenGrep results.
Formats results in clean tabular format suitable for Teams.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging
import yaml

logger = logging.getLogger(__name__)


def _get_ms_teams_result_limit() -> int:
    """Get the result limit for MS Teams notifications."""
    try:
        notifications_yaml = Path(__file__).parent.parent.parent / 'notifications.yaml'
        with open(notifications_yaml, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('settings', {}).get('result_limits', {}).get('ms_teams', 50)
    except Exception as e:
        logger.warning(f"Could not load MS Teams result limit from notifications.yaml: {e}, using default 50")
        return 50


def format_notifications(groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Format for Microsoft Teams - return multiple tables grouped by subtype."""
    tables = []
    
    # Map subtypes to friendly display names
    subtype_names = {
        'sast-python': 'SAST Python',
        'sast-javascript': 'SAST JavaScript', 
        'sast-golang': 'SAST Go',
        'sast-java': 'SAST Java',
        'sast-php': 'SAST PHP',
        'sast-ruby': 'SAST Ruby',
        'sast-csharp': 'SAST C#',
        'sast-dotnet': 'SAST .NET',
        'sast-c': 'SAST C',
        'sast-cpp': 'SAST C++',
        'sast-kotlin': 'SAST Kotlin',
        'sast-scala': 'SAST Scala',
        'sast-swift': 'SAST Swift',
        'sast-rust': 'SAST Rust',
        'sast-elixir': 'SAST Elixir',
        'sast-generic': 'SAST Generic'
    }
    
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    for subtype, items in groups.items():
        if not items:  # Skip empty groups
            continue
            
        rows = []
        for item in items:
            c = item['component']
            a = item['alert']
            props = a.get('props', {}) or {}
            full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
            
            try:
                file_name = Path(full_path).name
            except Exception:
                file_name = full_path
            
            severity = a.get('severity', '').lower()
            rows.append((
                severity_order.get(severity, 4),
                [
                    props.get('ruleId', a.get('title', '')),
                    a.get('severity', ''),
                    file_name,
                    full_path,
                    f"{props.get('startLine','')}-{props.get('endLine','')}",
                    (props.get('codeSnippet', '') or '')[:150]  # Truncate for Teams
                ]
            ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        # Apply truncation
        result_limit = _get_ms_teams_result_limit()
        total_results = len(rows)
        was_truncated = False
        
        if total_results > result_limit:
            logger.info(f"Truncating MS Teams OpenGrep results from {total_results} to {result_limit} (prioritized by severity)")
            rows = rows[:result_limit]
            was_truncated = True
        
        # Create a separate table for each subtype/language group
        display_name = subtype_names.get(subtype, subtype.upper())
        headers = ['Rule', 'Severity', 'File', 'Path', 'Lines', 'Code']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows) if rows else f"No {display_name} issues found."
        
        # Add truncation notice if needed
        if was_truncated:
            content += f"\n\n⚠️ Results truncated to {result_limit} highest severity findings (total: {total_results}). See full scan URL for complete results."
        
        tables.append({
            'title': display_name,
            'content': content
        })
    
    # Return list of tables - one per language group
    return tables