#!/usr/bin/env python3
"""
GitHub PR notifier for OpenGrep results.
Formats results with markdown for better GitHub display.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging
import yaml

logger = logging.getLogger(__name__)


def _get_github_pr_result_limit() -> int:
    """Get the result limit for GitHub PR notifications."""
    try:
        notifications_yaml = Path(__file__).parent.parent.parent / 'notifications.yaml'
        with open(notifications_yaml, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('settings', {}).get('result_limits', {}).get('github_pr', 100)
    except Exception as e:
        logger.warning(f"Could not load GitHub PR result limit from notifications.yaml: {e}, using default 100")
        return 100


def format_notifications(groups: Dict[str, List[Dict[str, Any]]], config=None) -> List[Dict[str, Any]]:
    """Format for GitHub PR comments - detailed with markdown formatting."""
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
    }
    
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    
    for subtype, items in groups.items():
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
            
            # Format code snippets with <pre> tags and <br> for line breaks
            code_snippet = props.get('codeSnippet', '') or ''
            if code_snippet:
                # Use <pre> tags for better code formatting as requested
                code_formatted = code_snippet.replace('\n', '<br>')
                if len(code_formatted) > 200:
                    code_formatted = code_formatted[:200] + '...'
                code_snippet = f"<pre>{code_formatted}</pre>"
            else:
                code_snippet = '-'
            
            severity = a.get('severity', '').lower()
            rows.append((
                severity_order.get(severity, 4),
                [
                    f"**{props.get('ruleId', a.get('title', ''))}**",
                    f"*{a.get('severity', '')}*",
                    f"`{file_name}`",
                    f"`{full_path}`",
                    f"Lines {props.get('startLine','')}-{props.get('endLine','')}",
                    code_snippet
                ]
            ))
        
        # Sort by severity and extract rows
        rows.sort(key=lambda x: x[0])
        rows = [row[1] for row in rows]
        
        # Apply truncation
        # result_limit = _get_github_pr_result_limit()
        total_results = len(rows)
        was_truncated = False
        #
        # if total_results > result_limit:
        #     logger.info(f"Truncating GitHub PR OpenGrep results from {total_results} to {result_limit} (prioritized by severity)")
        #     rows = rows[:result_limit]
        #     was_truncated = True
        
        # Create markdown table for this subtype
        display_name = subtype_names.get(subtype, subtype.upper())
        if not rows:
            content = f"No {display_name} issues found."
        else:
            headers = ['Rule', 'Severity', 'File', 'Path', 'Lines', 'Code']
            header_row = '| ' + ' | '.join(headers) + ' |'
            separator_row = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
            content_rows = []
            for row in rows:
                content_rows.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
            
            content = '\n'.join([header_row, separator_row] + content_rows)
            
            # Add truncation notice if needed
            # if was_truncated:
            #     content += f"\n\n⚠️ **Results truncated to {result_limit} highest severity findings** (total: {total_results}). See full scan URL for complete results."
        
        # Build title with repo/branch/commit info from config
        title_parts = ["Socket Security Results"]
        if config:
            if config.repo:
                title_parts.append(config.repo)
            if config.branch:
                title_parts.append(config.branch)
            if config.commit_hash:
                title_parts.append(config.commit_hash)
        
        title = " - ".join(title_parts)
        
        # Count total findings for summary
        total_findings = total_results if not was_truncated else total_results
        
        # Add summary section with scanner findings
        summary_content = f"""## Summary

| Scanner | Findings |
|---------|----------|
| {display_name} | {total_findings} |

## Details

{content}"""
        
        # Wrap content with HTML comment markers for section updates
        wrapped_content = f"""<!-- {subtype} start -->
# {title}

{summary_content}
<!-- {subtype} end -->"""
        
        tables.append({
            'title': title,
            'content': wrapped_content
        })
    
    return tables