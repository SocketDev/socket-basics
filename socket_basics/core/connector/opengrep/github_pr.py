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
        notifications_yaml = Path(__file__).parent.parent.parent.parent / 'notifications.yaml'
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
        'sast-python': 'Socket SAST Python',
        'sast-javascript': 'Socket SAST JavaScript', 
        'sast-golang': 'Socket SAST Go',
        'sast-java': 'Socket SAST Java',
        'sast-php': 'Socket SAST PHP',
        'sast-ruby': 'Socket SAST Ruby',
        'sast-csharp': 'Socket SAST C#',
        'sast-dotnet': 'Socket SAST .NET',
        'sast-c': 'Socket SAST C',
        'sast-cpp': 'Socket SAST C++',
        'sast-kotlin': 'Socket SAST Kotlin',
        'sast-scala': 'Socket SAST Scala',
        'sast-swift': 'Socket SAST Swift',
        'sast-rust': 'Socket SAST Rust',
    }
    
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '⚪'
    }
    
    for subtype, items in groups.items():
        # Group findings by file path, then by rule within each file
        file_groups = {}  # {file_path: {rule_id: [(severity, start, end, code_snippet), ...]}}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for item in items:
            c = item['component']
            a = item['alert']
            props = a.get('props', {}) or {}
            full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
            rule_id = props.get('ruleId', a.get('title', ''))
            severity = a.get('severity', '').lower()
            start_line = props.get('startLine', '')
            end_line = props.get('endLine', '')
            code_snippet = props.get('codeSnippet', '') or ''
            
            # Count by severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Group by file path
            if full_path not in file_groups:
                file_groups[full_path] = {}
            
            # Group by rule within file
            if rule_id not in file_groups[full_path]:
                file_groups[full_path][rule_id] = []
            
            file_groups[full_path][rule_id].append({
                'severity': severity,
                'start_line': start_line,
                'end_line': end_line,
                'code_snippet': code_snippet
            })
        
        # Build content in requested format
        display_name = subtype_names.get(subtype, f"Socket {subtype.upper()}")
        
        if not file_groups:
            content = f"✅ No issues found."
        else:
            content_lines = []
            
            # Add summary
            content_lines.append("### Summary")
            content_lines.append(f"{severity_emoji.get('critical', '🔴')} Critical: {severity_counts['critical']} | "
                                f"{severity_emoji.get('high', '🟠')} High: {severity_counts['high']} | "
                                f"{severity_emoji.get('medium', '🟡')} Medium: {severity_counts['medium']} | "
                                f"{severity_emoji.get('low', '⚪')} Low: {severity_counts['low']}")
            content_lines.append("")
            content_lines.append("### Details")
            content_lines.append("")
            
            # Sort files by highest severity finding in each file
            file_severity_list = []
            for file_path in file_groups.keys():
                # Find the highest severity (lowest number) in this file
                min_severity = 999
                for rule_id, locations in file_groups[file_path].items():
                    for loc in locations:
                        sev = severity_order.get(loc['severity'], 4)
                        if sev < min_severity:
                            min_severity = sev
                file_severity_list.append((min_severity, file_path))
            
            # Sort by severity first, then by file path
            file_severity_list.sort(key=lambda x: (x[0], x[1]))
            
            for _, file_path in file_severity_list:
                try:
                    file_name = Path(file_path).name
                except Exception:
                    file_name = file_path
                
                # File header
                content_lines.append(f"#### `{file_path}`")
                content_lines.append("")
                
                # Sort rules by severity within file
                rules_in_file = []
                for rule_id, locations in file_groups[file_path].items():
                    # Get highest severity for this rule
                    min_severity = min(severity_order.get(loc['severity'], 4) for loc in locations)
                    rules_in_file.append((min_severity, rule_id, locations))
                
                rules_in_file.sort(key=lambda x: x[0])
                
                # Output each rule with its locations
                for _, rule_id, locations in rules_in_file:
                    # Get severity from first location (they should all be same rule)
                    rule_severity = locations[0]['severity']
                    emoji = severity_emoji.get(rule_severity, '⚪')
                    
                    content_lines.append(f"**{rule_id}**  ")
                    content_lines.append(f"{emoji} *{rule_severity.upper()}*")
                    content_lines.append("")
                    
                    # Output each location with code snippet
                    for loc in locations:
                        content_lines.append(f"**Lines {loc['start_line']}:{loc['end_line']}**")
                        if loc['code_snippet']:
                            # Format code snippet in code block
                            content_lines.append("```")
                            content_lines.append(loc['code_snippet'])
                            content_lines.append("```")
                        content_lines.append("")
            
            content = '\n'.join(content_lines)
        
        # Build title
        title_parts = [display_name]
        if config:
            if config.repo:
                title_parts.append(config.repo)
            if config.branch:
                title_parts.append(config.branch)
            if config.commit_hash:
                title_parts.append(config.commit_hash[:8])  # Short hash
        
        title = " - ".join(title_parts)
        
        # Wrap content with HTML comment markers for section updates
        wrapped_content = f"""<!-- {subtype} start -->
# {title}

{content}
<!-- {subtype} end -->"""
        
        tables.append({
            'title': title,
            'content': wrapped_content
        })
    
    return tables