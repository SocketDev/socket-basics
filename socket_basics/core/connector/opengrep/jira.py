#!/usr/bin/env python3
"""
Jira notifier for OpenGrep results.
Formats results for Jira tickets with priority mapping and detailed descriptions.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def _get_jira_result_limit() -> int:
    """Get the Jira result limit from notifications config, with fallback to default."""
    try:
        import yaml
        
        # Try to load notifications.yaml to get the limit
        base_dir = Path(__file__).parent.parent.parent
        notifications_path = base_dir / "notifications.yaml"
        
        if notifications_path.exists():
            with open(notifications_path, 'r') as f:
                config = yaml.safe_load(f)
                result_limits = config.get('settings', {}).get('result_limits', {})
                return result_limits.get('jira', result_limits.get('default', 30))
    except Exception as e:
        logger.debug(f"Could not load Jira result limit from config: {e}")
    
    # Fallback to conservative default
    return 30


def format_notifications(groups: Dict[str, List[Dict[str, Any]]], config=None) -> List[Dict[str, Any]]:
    """Format for Jira tickets - using panels instead of tables for better control."""
    results = []
    
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
    
    # Define severity ranking for sorting
    severity_rank = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3
    }
    
    for subtype, items in groups.items():
        display_name = subtype_names.get(subtype, subtype.upper())
        
        if not items:
            content = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": f"No {display_name} issues found."}]
                    }
                ]
            }
        else:
            # Sort items by severity (Critical -> High -> Medium -> Low)
            sorted_items = sorted(
                items, 
                key=lambda x: severity_rank.get(
                    x['alert'].get('severity', '').lower(), 
                    999  # Unknown severities go to the end
                )
            )
            
            # Get Jira-specific result limit and truncate if needed
            max_items = _get_jira_result_limit()
            truncated_count = 0
            if len(sorted_items) > max_items:
                truncated_count = len(sorted_items) - max_items
                sorted_items = sorted_items[:max_items]
                logger.info(f"Truncated {display_name} results from {len(items)} to {max_items} for Jira")
            
            panels = []
            
            for item in sorted_items:
                c = item['component']
                a = item['alert']
                props = a.get('props', {}) or {}
                full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
                
                try:
                    file_name = Path(full_path).name
                except Exception:
                    file_name = full_path
                
                # Map severity to Jira priority
                severity = a.get('severity', '').lower()
                jira_priority = {
                    'critical': 'Highest',
                    'high': 'High',
                    'medium': 'Medium', 
                    'low': 'Low'
                }.get(severity, 'Medium')
                
                rule_id = props.get('ruleId', a.get('title', ''))
                description = a.get('description', '')
                
                # Determine panel color based on priority
                panel_type = {
                    'Highest': 'error',
                    'High': 'warning',
                    'Medium': 'note',
                    'Low': 'info'
                }.get(jira_priority, 'note')
                
                # Build panel content
                panel_content = [
                    {
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [{"type": "text", "text": f"🔍 {rule_id}", "marks": [{"type": "strong"}]}]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "File: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": full_path, "marks": [{"type": "code"}]}
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "Description: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": description}
                        ]
                    }
                ]
                
                # Add code snippet if available
                code_snippet = props.get('codeSnippet', '') or ''
                if code_snippet:
                    # Determine language from subtype
                    language_map = {
                        'sast-python': 'python',
                        'sast-javascript': 'javascript', 
                        'sast-golang': 'go',
                        'sast-java': 'java',
                        'sast-php': 'php',
                        'sast-ruby': 'ruby',
                        'sast-csharp': 'c#',
                        'sast-dotnet': 'c#',
                        'sast-c': 'c',
                        'sast-cpp': 'c++',
                        'sast-kotlin': 'scala',
                        'sast-scala': 'scala',
                        'sast-swift': 'swift',
                        'sast-rust': 'javascript',
                    }
                    language = language_map.get(subtype, 'javascript')
                    
                    start_line = props.get('startLine', '')
                    end_line = props.get('endLine', '')
                    
                    panel_content.extend([
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": f"Code (Lines {start_line}-{end_line}):", "marks": [{"type": "strong"}]}
                            ]
                        },
                        {
                            "type": "codeBlock",
                            "attrs": {"language": language},
                            "content": [{"type": "text", "text": code_snippet}]
                        }
                    ])
                
                # Create the panel
                panels.append({
                    "type": "panel",
                    "attrs": {"panelType": panel_type},
                    "content": panel_content
                })
                
                # Add a rule/divider between issues
                panels.append({
                    "type": "rule"
                })
            
            # Remove the last rule
            if panels and panels[-1]["type"] == "rule":
                panels.pop()
            
            # Add truncation notice if results were truncated
            if truncated_count > 0:
                truncation_panel = {
                    "type": "panel",
                    "attrs": {"panelType": "info"},
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "⚠️ ", "marks": [{"type": "strong"}]},
                                {"type": "text", "text": f"Showing top {max_items} results (by severity). "},
                                {"type": "text", "text": f"{truncated_count} additional results truncated. "},
                                {"type": "text", "text": "View full results at the scan URL below."}
                            ]
                        }
                    ]
                }
                panels.append(truncation_panel)
            
            content = {
                "type": "doc",
                "version": 1,
                "content": panels
            }
        
        results.append({
            'title': display_name,
            'content': content
        })
    
    return results