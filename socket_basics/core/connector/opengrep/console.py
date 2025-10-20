#!/usr/bin/env python3
"""
Console notifier for OpenGrep results.
Formats results for human-readable console output with truncated content.
"""

from pathlib import Path
from typing import Dict, Any, List


def format_notifications(groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Format for console output - return multiple tables grouped by subtype."""
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
            
            # Truncate for console readability
            code_snippet = props.get('codeSnippet', '') or ''
            if len(code_snippet) > 80:
                code_snippet = code_snippet[:77] + '...'
            
            rows.append([
                props.get('ruleId', a.get('title', '')),
                a.get('severity', ''),
                file_name,
                full_path,
                f"{props.get('startLine','')}-{props.get('endLine','')}",
                code_snippet
            ])
        
        # Create a separate table for each subtype/language group
        from tabulate import tabulate
        
        display_name = subtype_names.get(subtype, subtype.upper())
        headers = ['Rule', 'Severity', 'File', 'Path', 'Lines', 'Code']
        table_content = tabulate(rows, headers=headers, tablefmt='grid') if rows else f"No {display_name} issues found."
        
        tables.append({
            'title': display_name,
            'content': table_content
        })
    
    # Return list of tables - one per language group
    return tables