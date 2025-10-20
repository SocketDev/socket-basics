"""
Slack text formatter for Socket Security Basics.

This module provides text formatting for Slack notifications, converting
security findings into readable text format suitable for Slack messages.
Note: This converts findings to text rather than Slack Block Kit format.
"""

from typing import Any, List
from .base import TableFormatter

# Slack limits
MAX_SLACK_MESSAGE_SIZE = 40000  # Conservative limit for Slack messages


class SlackFormatter(TableFormatter):
    """Formatter for Slack text messages."""
    
    def __init__(self):
        super().__init__(max_content_length=MAX_SLACK_MESSAGE_SIZE)
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as Slack-friendly text.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            Formatted text suitable for Slack
        """
        if not findings:
            return f"*{title}*\nNo findings to report."
        
        # Format as text blocks rather than table
        output_lines = [f"*{title}*", ""]
        
        for i, finding in enumerate(findings, 1):
            component = self._extract_column_value(finding, 'component') or 'Unknown'
            severity = self._extract_column_value(finding, 'severity') or 'Unknown'
            title_text = self._extract_column_value(finding, 'title') or 'No description'
            file_path = self._extract_column_value(finding, 'file') or ''
            line_num = self._extract_column_value(finding, 'line') or ''
            
            # Format as Slack-style message
            location = f" in `{file_path}`" if file_path else ""
            if line_num:
                location += f" (line {line_num})"
            
            severity_emoji = self._get_severity_emoji(severity)
            
            output_lines.append(f"{i}. {severity_emoji} *{severity.upper()}* - {component}")
            output_lines.append(f"   {title_text}{location}")
            output_lines.append("")
        
        content = "\n".join(output_lines)
        return self.truncate_content(content)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as Slack-friendly text.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            Formatted text suitable for Slack
        """
        if not rows:
            return f"*{title}*\nNo data to display."
        
        output_lines = [f"*{title}*", ""]
        
        # Format as list items rather than table
        for i, row in enumerate(rows, 1):
            row_parts = []
            for j, cell in enumerate(row):
                if j < len(headers):
                    header = headers[j]
                    cell_str = self.sanitize_text(cell)
                    row_parts.append(f"*{header}:* {cell_str}")
            
            output_lines.append(f"{i}. {' | '.join(row_parts)}")
        
        output_lines.append("")
        content = "\n".join(output_lines)
        return self.truncate_content(content)
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level.
        
        Args:
            severity: Severity level string
            
        Returns:
            Appropriate emoji for severity
        """
        severity_lower = str(severity).lower()
        
        if severity_lower in ['critical', 'high']:
            return "🚨"
        elif severity_lower in ['medium', 'moderate']:
            return "⚠️"
        elif severity_lower in ['low', 'info']:
            return "ℹ️"
        else:
            return "🔍"