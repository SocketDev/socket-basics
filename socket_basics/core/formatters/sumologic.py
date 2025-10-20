"""
SumoLogic log formatter for Socket Security Basics.

This module provides log formatting for SumoLogic, converting security findings
into structured log entries suitable for SumoLogic ingestion.
"""

import json
from datetime import datetime
from typing import Any, List
from .base import TableFormatter


class SumologicFormatter(TableFormatter):
    """Formatter for SumoLogic log events."""
    
    def __init__(self):
        super().__init__(max_content_length=None)  # No strict limit for logs
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as SumoLogic log events.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            JSON log entries suitable for SumoLogic
        """
        if not findings:
            empty_event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": "INFO",
                "source": "socket-security",
                "category": title,
                "message": "No findings to report",
                "findings_count": 0
            }
            return json.dumps(empty_event, indent=2)
        
        # Create individual log events for each finding
        log_events = []
        for finding in findings:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": self._get_log_level(self._extract_column_value(finding, 'severity')),
                "source": "socket-security",
                "category": title,
                "component": self._extract_column_value(finding, 'component') or 'Unknown',
                "severity": self._extract_column_value(finding, 'severity') or 'Unknown',
                "title": self._extract_column_value(finding, 'title') or 'No description',
                "file_path": self._extract_column_value(finding, 'file') or '',
                "line_number": self._extract_column_value(finding, 'line') or '',
                "raw_finding": finding
            }
            log_events.append(event)
        
        # Return as newline-delimited JSON (NDJSON) for log ingestion
        return "\n".join(json.dumps(event, ensure_ascii=False) for event in log_events)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as SumoLogic log events.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            JSON log entries suitable for SumoLogic
        """
        if not rows:
            empty_event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": "INFO",
                "source": "socket-security",
                "category": title,
                "message": "No data to display",
                "row_count": 0
            }
            return json.dumps(empty_event, indent=2)
        
        # Create log events for table data
        log_events = []
        for i, row in enumerate(rows):
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": "INFO",
                "source": "socket-security",
                "category": title,
                "row_index": i + 1
            }
            
            # Add column data as event properties
            for j, header in enumerate(headers):
                if j < len(row):
                    # Clean header name for property key
                    prop_key = header.lower().replace(" ", "_").replace("-", "_")
                    event[prop_key] = self.sanitize_text(row[j])
            
            log_events.append(event)
        
        # Return as newline-delimited JSON (NDJSON)
        return "\n".join(json.dumps(event, ensure_ascii=False) for event in log_events)
    
    def _get_log_level(self, severity: str) -> str:
        """Convert security severity to log level.
        
        Args:
            severity: Security severity level
            
        Returns:
            Appropriate log level for SumoLogic
        """
        severity_lower = str(severity).lower()
        
        if severity_lower in ['critical']:
            return "FATAL"
        elif severity_lower in ['high']:
            return "ERROR"
        elif severity_lower in ['medium', 'moderate']:
            return "WARN"
        elif severity_lower in ['low', 'info']:
            return "INFO"
        else:
            return "DEBUG"