"""
JIRA text formatter for Socket Security Basics.

This module provides text formatting for JIRA notifications, converting
security findings into readable text format suitable for JIRA comments.
Note: This converts findings to text rather than Atlassian Document Format (ADF).
"""

from typing import Any, List
from .base import TableFormatter

# JIRA limits
MAX_JIRA_COMMENT_LENGTH = 32767  # JIRA comment length limit


class JiraFormatter(TableFormatter):
    """Formatter for JIRA text comments."""
    
    def __init__(self):
        super().__init__(max_content_length=MAX_JIRA_COMMENT_LENGTH)
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as JIRA-friendly text.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            Formatted text suitable for JIRA
        """
        if not findings:
            return f"h3. {title}\n\nNo findings to report."
        
        # Format using JIRA text formatting
        output_lines = [f"h3. {title}", ""]
        
        for i, finding in enumerate(findings, 1):
            component = self._extract_column_value(finding, 'component') or 'Unknown'
            severity = self._extract_column_value(finding, 'severity') or 'Unknown'
            title_text = self._extract_column_value(finding, 'title') or 'No description'
            file_path = self._extract_column_value(finding, 'file') or ''
            line_num = self._extract_column_value(finding, 'line') or ''
            
            # Format as JIRA-style text
            location = f" in {{code}}{file_path}{{code}}" if file_path else ""
            if line_num:
                location += f" (line {line_num})"
            
            severity_color = self._get_severity_color(severity)
            
            output_lines.append(f"{i}. {severity_color}*{severity.upper()}*{severity_color} - {component}")
            output_lines.append(f"   {title_text}{location}")
            output_lines.append("")
        
        content = "\n".join(output_lines)
        return self.truncate_content(content)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as JIRA-friendly text.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            Formatted text suitable for JIRA
        """
        if not rows:
            return f"h3. {title}\n\nNo data to display."
        
        # Format as JIRA table
        output_lines = [f"h3. {title}", ""]
        
        # JIRA table header
        header_row = "|| " + " || ".join(headers) + " ||"
        output_lines.append(header_row)
        
        # JIRA table rows
        for row in rows:
            sanitized_row = [self._sanitize_cell_for_jira(cell) for cell in row]
            data_row = "| " + " | ".join(sanitized_row) + " |"
            output_lines.append(data_row)
        
        output_lines.append("")
        content = "\n".join(output_lines)
        return self.truncate_content(content)
    
    def _sanitize_cell_for_jira(self, cell: Any) -> str:
        """Sanitize table cell values for JIRA display.
        
        Args:
            cell: The cell value to sanitize
            
        Returns:
            Sanitized string suitable for JIRA table
        """
        cell_str = self.sanitize_text(cell)
        
        # Escape JIRA special characters
        cell_str = cell_str.replace("|", "\\|")
        cell_str = cell_str.replace("\n", " ")
        
        # Limit cell length for readability
        if len(cell_str) > 200:
            cell_str = cell_str[:197] + "..."
        
        return cell_str
    
    def _get_severity_color(self, severity: str) -> str:
        """Get JIRA color markup for severity level.
        
        Args:
            severity: Severity level string
            
        Returns:
            Appropriate JIRA color markup for severity
        """
        severity_lower = str(severity).lower()
        
        if severity_lower in ['critical', 'high']:
            return "{color:red}"
        elif severity_lower in ['medium', 'moderate']:
            return "{color:orange}"
        elif severity_lower in ['low', 'info']:
            return "{color:blue}"
        else:
            return "{color:gray}"