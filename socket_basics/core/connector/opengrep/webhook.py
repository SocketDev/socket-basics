#!/usr/bin/env python3
"""
Webhook notifier for OpenGrep results.
Formats results for generic webhook consumption with flexible structured format.
"""

from pathlib import Path
from typing import Dict, Any, List


def format_notifications(groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Format for generic webhook - return multiple flexible structured datasets grouped by subtype."""
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
            
            rows.append([
                props.get('ruleId', a.get('title', '')),
                a.get('severity', ''),
                file_name,
                full_path,
                f"{props.get('startLine','')}-{props.get('endLine','')}",
                props.get('codeSnippet', '') or '',
                subtype,
                'opengrep'
            ])
        
        # Create a separate dataset for each subtype/language group
        display_name = subtype_names.get(subtype, subtype.upper())
        headers = ['Rule', 'Severity', 'File', 'Path', 'Lines', 'Code', 'SubType', 'Scanner']
        header_row = ' | '.join(headers)
        separator_row = ' | '.join(['---'] * len(headers))
        content_rows = []
        for row in rows:
            content_rows.append(' | '.join(str(cell) for cell in row))
        
        content = '\n'.join([header_row, separator_row] + content_rows) if rows else f"No {display_name} issues found."
        
        tables.append({
            'title': display_name,
            'content': content
        })
    
    # Return list of tables - one per language group
    return tables