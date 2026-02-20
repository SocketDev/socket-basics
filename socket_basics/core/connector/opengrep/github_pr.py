#!/usr/bin/env python3
"""
GitHub PR notifier for OpenGrep results.
Formats results with markdown for better GitHub display.
"""

from pathlib import Path
from typing import Dict, Any, List
import logging
import yaml
from socket_basics.core.notification import github_pr_helpers as helpers

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

    # Get feature flags from config (using shared helper)
    flags = helpers.get_feature_flags(config)
    enable_links = flags['enable_links']
    enable_collapse = flags['enable_collapse']
    collapse_non_critical = flags['collapse_non_critical']
    enable_code_fencing = flags['enable_code_fencing']
    show_rule_names = flags['show_rule_names']
    repository = flags['repository']
    commit_hash = flags['commit_hash']
    full_scan_url = flags['full_scan_url']

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

    # Use shared severity constants
    severity_order = helpers.SEVERITY_ORDER
    severity_emoji = helpers.SEVERITY_EMOJI
    
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
            raw_start = props.get('startLine', '')
            raw_end = props.get('endLine', '')
            start_line = int(raw_start) if raw_start and str(raw_start).isdigit() else None
            end_line = int(raw_end) if raw_end and str(raw_end).isdigit() else None
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
                # Clean workspace prefixes for display
                display_path = helpers.clean_filepath(file_path)
                try:
                    file_name = Path(display_path).name
                except Exception:
                    file_name = display_path

                # Calculate severity counts for this file (for collapsible summary)
                file_severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for rule_id, locations in file_groups[file_path].items():
                    for loc in locations:
                        sev = loc['severity']
                        if sev in file_severities:
                            file_severities[sev] += 1

                # Sort rules by severity within file
                rules_in_file = []
                for rule_id, locations in file_groups[file_path].items():
                    # Get highest severity for this rule
                    min_severity = min(severity_order.get(loc['severity'], 4) for loc in locations)
                    rules_in_file.append((min_severity, rule_id, locations))

                rules_in_file.sort(key=lambda x: x[0])

                # Build file section content
                file_content_lines = []

                # Output each rule with its locations
                for _, rule_id, locations in rules_in_file:
                    # Get severity from first location (they should all be same rule)
                    rule_severity = locations[0]['severity']
                    emoji = severity_emoji.get(rule_severity, '⚪')

                    # Show rule name
                    if show_rule_names:
                        file_content_lines.append(f"{emoji} **{rule_id}**: *{rule_severity.upper()}*")
                    else:
                        file_content_lines.append(f"{emoji} *{rule_severity.upper()}*")
                    file_content_lines.append("")

                    # Output each location with code snippet
                    for loc in locations:
                        # Create clickable file location link
                        location_link = helpers.format_file_location_link(
                            file_path,
                            loc['start_line'],
                            loc['end_line'],
                            repository,
                            commit_hash,
                            enable_links
                        )
                        file_content_lines.append(location_link)

                        if loc['code_snippet']:
                            # Format code snippet with language-aware fencing
                            code_block = helpers.format_code_block(
                                loc['code_snippet'],
                                filepath=file_path,
                                enable_fencing=enable_code_fencing
                            )
                            file_content_lines.append(code_block)
                        file_content_lines.append("")

                file_content = '\n'.join(file_content_lines)

                # Add collapsible section or plain header
                if enable_collapse:
                    # Determine if this should be auto-expanded
                    has_critical = file_severities['critical'] > 0
                    # Auto-expand if: no collapse requested OR has critical findings
                    auto_expand = (not collapse_non_critical) or has_critical

                    collapsible = helpers.create_collapsible_section(
                        display_path,  # Don't use backticks in summary - they don't render in GitHub
                        file_content,
                        severity_counts=file_severities,
                        auto_expand=auto_expand
                    )
                    content_lines.append(collapsible)
                else:
                    content_lines.append(f"#### `{display_path}`")
                    content_lines.append("")
                    content_lines.append(file_content)
            
            content = '\n'.join(content_lines)
        
        # Build title - just scanner name (repo/branch context already visible in PR)
        title = display_name

        # Wrap in standard PR comment section
        wrapped_content = helpers.wrap_pr_comment_section(
            subtype, title, content, full_scan_url
        )
        
        tables.append({
            'title': title,
            'content': wrapped_content
        })
    
    return tables