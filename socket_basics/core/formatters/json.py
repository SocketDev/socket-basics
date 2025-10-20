"""
JSON formatter for Socket Security Basics.

This module provides JSON formatting functionality, converting security findings
into structured JSON suitable for JSON-based notifications.
"""

import json
from typing import Any, List
from .base import BaseFormatter


class JsonFormatter(BaseFormatter):
    """Formatter for JSON-based content."""
    
    def __init__(self):
        super().__init__(max_content_length=None)  # No limit for JSON
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as JSON.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            JSON string representation of findings
        """
        output = {
            "title": title,
            "findings": findings,
            "count": len(findings)
        }
        
        return json.dumps(output, indent=2, ensure_ascii=False)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as JSON.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            JSON string representation of table data
        """
        # Convert rows to list of dictionaries
        table_data = []
        for row in rows:
            row_dict = {}
            for i, header in enumerate(headers):
                value = row[i] if i < len(row) else ""
                row_dict[header] = value
            table_data.append(row_dict)
        
        output = {
            "title": title,
            "headers": headers,
            "data": table_data,
            "count": len(table_data)
        }
        
        return json.dumps(output, indent=2, ensure_ascii=False)