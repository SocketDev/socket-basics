"""
Base formatter interface for Socket Security Basics.

This module defines the abstract base class and common patterns for all formatters.
Each formatter converts raw security findings into text-based content suitable
for specific notification channels.
"""

import abc
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class BaseFormatter(abc.ABC):
    """Abstract base class for security findings formatters."""
    
    def __init__(self, max_content_length: Optional[int] = None):
        """Initialize the formatter.
        
        Args:
            max_content_length: Maximum content length before truncation
        """
        self.max_content_length = max_content_length
    
    @abc.abstractmethod
    def format_findings(self, findings: List[Dict[str, Any]], title: str = "Security Findings") -> str:
        """Format security findings into text content.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            Formatted text content suitable for the target platform
        """
        pass
    
    @abc.abstractmethod
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data into text content.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            Formatted table as text content
        """
        pass
    
    def truncate_content(self, content: str, suffix: str = "...") -> str:
        """Truncate content if it exceeds maximum length.
        
        Args:
            content: Content to potentially truncate
            suffix: Suffix to append when truncating
            
        Returns:
            Original content or truncated content with suffix
        """
        if not self.max_content_length or len(content) <= self.max_content_length:
            return content
        
        truncate_at = self.max_content_length - len(suffix)
        return content[:truncate_at] + suffix
    
    def sanitize_text(self, text: Any) -> str:
        """Sanitize and normalize text values.
        
        Args:
            text: Text value to sanitize
            
        Returns:
            Sanitized string
        """
        if text is None:
            return ""
        
        text_str = str(text)
        # Remove or replace problematic characters for text display
        return text_str.replace('\r\n', '\n').replace('\r', '\n')


class TableFormatter(BaseFormatter):
    """Base class for table-based formatters."""
    
    def format_findings_as_table(
        self, 
        findings: List[Dict[str, Any]], 
        columns: List[str], 
        title: str = "Security Findings"
    ) -> str:
        """Format findings as a table using specified columns.
        
        Args:
            findings: List of finding dictionaries
            columns: Column names to extract from findings
            title: Title for the table
            
        Returns:
            Formatted table content
        """
        if not findings:
            return f"{title}: No findings to report."
        
        # Extract rows from findings
        rows = []
        for finding in findings:
            row = []
            for col in columns:
                value = self._extract_column_value(finding, col)
                row.append(value)
            rows.append(row)
        
        return self.format_table(columns, rows, title)
    
    def _extract_column_value(self, finding: Dict[str, Any], column: str) -> Any:
        """Extract a column value from a finding dictionary.
        
        Args:
            finding: Finding dictionary
            column: Column name to extract
            
        Returns:
            Extracted value or empty string if not found
        """
        # Handle common column mappings
        column_mappings = {
            'rule': ['rule', 'rule_id', 'check', 'check_name'],
            'file': ['file', 'filename', 'path', 'location'],
            'line': ['line', 'line_number', 'start_line'],
            'severity': ['severity', 'level'],
            'title': ['title', 'description', 'message'],
            'component': ['component', 'id', 'name']
        }
        
        # Try direct access first
        if column in finding:
            return finding[column]
        
        # Try mapped alternatives
        for mapped_column in column_mappings.get(column.lower(), [column]):
            if mapped_column in finding:
                return finding[mapped_column]
        
        # Try nested access for common patterns
        if 'props' in finding and isinstance(finding['props'], dict):
            if column in finding['props']:
                return finding['props'][column]
        
        if 'location' in finding and isinstance(finding['location'], dict):
            if column in finding['location']:
                return finding['location'][column]
        
        return ""