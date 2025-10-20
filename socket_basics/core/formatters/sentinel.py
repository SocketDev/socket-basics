"""
Microsoft Sentinel log formatter for Socket Security Basics.

This module provides log formatting for Microsoft Sentinel/Azure Log Analytics,
converting security findings into structured log entries.
"""

import json
from datetime import datetime
from typing import Any, List
from .base import TableFormatter


class SentinelFormatter(TableFormatter):
    """Formatter for Microsoft Sentinel log events."""
    
    def __init__(self):
        super().__init__(max_content_length=None)  # No strict limit for logs
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as Sentinel log events.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            JSON log entries suitable for Sentinel
        """
        if not findings:
            empty_event = {
                "TimeGenerated": datetime.utcnow().isoformat() + "Z",
                "EventType": "SecurityScan",
                "Category": title,
                "Message": "No findings to report",
                "FindingsCount": 0
            }
            return json.dumps(empty_event, indent=2)
        
        # Create individual log events for each finding
        log_events = []
        for finding in findings:
            event = {
                "TimeGenerated": datetime.utcnow().isoformat() + "Z",
                "EventType": "SecurityFinding",
                "Category": title,
                "Component": self._extract_column_value(finding, 'component') or 'Unknown',
                "Severity": self._extract_column_value(finding, 'severity') or 'Unknown',
                "Title": self._extract_column_value(finding, 'title') or 'No description',
                "FilePath": self._extract_column_value(finding, 'file') or '',
                "LineNumber": self._extract_column_value(finding, 'line') or '',
                "RawFinding": finding
            }
            log_events.append(event)
        
        # Return as newline-delimited JSON (NDJSON) for log ingestion
        return "\n".join(json.dumps(event, ensure_ascii=False) for event in log_events)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as Sentinel log events.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            JSON log entries suitable for Sentinel
        """
        if not rows:
            empty_event = {
                "TimeGenerated": datetime.utcnow().isoformat() + "Z",
                "EventType": "SecurityScan",
                "Category": title,
                "Message": "No data to display",
                "RowCount": 0
            }
            return json.dumps(empty_event, indent=2)
        
        # Create log events for table data
        log_events = []
        for i, row in enumerate(rows):
            event = {
                "TimeGenerated": datetime.utcnow().isoformat() + "Z",
                "EventType": "SecurityTableRow",
                "Category": title,
                "RowIndex": i + 1
            }
            
            # Add column data as event properties
            for j, header in enumerate(headers):
                if j < len(row):
                    # Clean header name for property key
                    prop_key = header.replace(" ", "").replace("-", "").replace("_", "")
                    event[prop_key] = self.sanitize_text(row[j])
            
            log_events.append(event)
        
        # Return as newline-delimited JSON (NDJSON)
        return "\n".join(json.dumps(event, ensure_ascii=False) for event in log_events)