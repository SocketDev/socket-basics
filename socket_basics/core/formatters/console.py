"""
Console table formatter for Socket Security Basics.

This module provides console/terminal table formatting functionality,
converting security findings into readable text tables.
"""

from typing import Any, List
from .base import TableFormatter

# Console display limits
MAX_CELL_LENGTH = 200
DEFAULT_TRUNCATION_SUFFIX = "..."


class ConsoleFormatter(TableFormatter):
    """Formatter for console/terminal table display."""
    
    def __init__(self):
        super().__init__(max_content_length=None)  # No global limit for console
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as a console table.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            Formatted console table as text
        """
        if not findings:
            return f"{title}: No findings to report."
        
        # Standard columns for security findings
        columns = ['component', 'severity', 'title', 'file', 'line']
        return self.format_findings_as_table(findings, columns, title)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as a console table.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            Formatted console table as text
        """
        if not rows:
            return f"{title}: No data to display."
        
        # Try to use tabulate if available, fallback to simple formatting
        try:
            from tabulate import tabulate
            
            # Sanitize all cells for console display
            sanitized_rows = []
            for row in rows:
                sanitized_row = [self._sanitize_cell_for_console(cell) for cell in row]
                sanitized_rows.append(sanitized_row)
            
            table_content = tabulate(sanitized_rows, headers=headers, tablefmt="grid")
            
            # Add title
            output_lines = [f"\n{title.upper()}", "-" * len(title), "", table_content, ""]
            return "\n".join(output_lines)
            
        except ImportError:
            # Fallback to simple table formatting
            return self._simple_table_format(headers, rows, title)
    
    def _simple_table_format(self, headers: List[str], rows: List[List[Any]], title: str) -> str:
        """Simple table formatting fallback when tabulate is not available.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            Simple formatted table as text
        """
        # Sanitize all cells for console display
        sanitized_rows = []
        for row in rows:
            sanitized_row = [self._sanitize_cell_for_console(cell) for cell in row]
            sanitized_rows.append(sanitized_row)
        
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in sanitized_rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build table
        output_lines = []
        
        # Title
        output_lines.append(f"\n{title.upper()}")
        output_lines.append("-" * len(title))
        output_lines.append("")
        
        # Header row
        header_row = " | ".join(
            header.ljust(col_widths[i]) for i, header in enumerate(headers)
        )
        output_lines.append(header_row)
        
        # Header separator
        separator = "-+-".join("-" * width for width in col_widths)
        output_lines.append(separator)
        
        # Data rows
        for row in sanitized_rows:
            data_row = " | ".join(
                str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
            )
            output_lines.append(data_row)
        
        output_lines.append("")
        return "\n".join(output_lines)
    
    def _sanitize_cell_for_console(self, cell: Any, max_length: int = MAX_CELL_LENGTH) -> str:
        """Sanitize table cell values for console display.
        
        Args:
            cell: The cell value to sanitize
            max_length: Maximum length before truncation
            
        Returns:
            Sanitized string suitable for console display
        """
        cell_str = self.sanitize_text(cell)
        
        # Truncate very long strings
        if len(cell_str) > max_length:
            truncate_at = max_length - len(DEFAULT_TRUNCATION_SUFFIX)
            cell_str = cell_str[:truncate_at] + DEFAULT_TRUNCATION_SUFFIX
        
        # Replace newlines with spaces for table display
        return " ".join(cell_str.split())


def format_console_section(title: str, content: str, separator_char: str = "-") -> str:
    """Format a titled section for console display.
    
    Args:
        title: Section title
        content: Section content
        separator_char: Character to use for title underline
        
    Returns:
        Formatted section string with title, separator, and content
    """
    formatted_title = title.upper()
    separator = separator_char * len(formatted_title)
    
    return f"\n{formatted_title}\n{separator}\n{content}\n"


def build_console_output_from_notifications(notifications: List[dict]) -> str:
    """Build formatted console output from notification data.
    
    Args:
        notifications: List of dicts with 'title' and 'content' keys
        
    Returns:
        Formatted string ready for console display
    """
    if not notifications:
        return "No notifications to display."
    
    output_sections = []
    for notification in notifications:
        if not isinstance(notification, dict):
            continue
            
        title = notification.get('title', 'Untitled')
        content = notification.get('content', 'No content')
        
        section = format_console_section(title, content)
        output_sections.append(section)
    
    return "".join(output_sections)