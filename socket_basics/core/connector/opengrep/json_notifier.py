#!/usr/bin/env python3
"""
JSON notifier for OpenGrep results.
Formats results with complete structured data for programmatic consumption.
"""

from pathlib import Path
from typing import Dict, Any, List


def format_notifications(groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Format for JSON output - return multiple structured datasets grouped by subtype."""
    import json
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
            
        structured_data = []
        for item in items:
            c = item['component']
            a = item['alert']
            props = a.get('props', {}) or {}
            full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
            
            try:
                file_name = Path(full_path).name
            except Exception:
                file_name = full_path
            
            structured_data.append({
                'rule': props.get('ruleId', a.get('title', '')),
                'severity': a.get('severity', ''),
                'file_name': file_name,
                'file_path': full_path,
                'lines': f"{props.get('startLine','')}-{props.get('endLine','')}",
                'code_snippet': props.get('codeSnippet', '') or '',
                'subtype': subtype,
                'description': a.get('description', ''),
                'confidence': props.get('confidence', ''),
                'fingerprint': props.get('fingerprint', '')
            })
        
        # Create JSON content for this subtype
        display_name = subtype_names.get(subtype, subtype.upper())
        content = json.dumps({
            'results': structured_data,
            'metadata': {
                'subtype': subtype,
                'display_name': display_name,
                'total_issues': len(structured_data)
            }
        }, indent=2)
        
        tables.append({
            'title': display_name,
            'content': content
        })
    
    # Return list of tables - one per language group
    return tables