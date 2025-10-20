"""
Webhook payload formatter for Socket Security Basics.

This module provides JSON formatting for webhook notifications, converting 
security findings into structured payloads suitable for webhook endpoints.
"""

import json
from datetime import datetime
from typing import Any, List
from .base import TableFormatter


class WebhookFormatter(TableFormatter):
    """Formatter for webhook JSON payloads."""
    
    def __init__(self):
        super().__init__(max_content_length=None)  # No strict limit for webhooks
    
    def format_findings(self, findings: List[dict], title: str = "Security Findings") -> str:
        """Format security findings as webhook payload.
        
        Args:
            findings: List of finding dictionaries
            title: Title for the formatted content
            
        Returns:
            JSON payload suitable for webhook endpoints
        """
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "security_scan_completed",
            "title": title,
            "summary": {
                "total_findings": len(findings),
                "severities": self._count_severities(findings)
            },
            "findings": []
        }
        
        # Format each finding
        for finding in findings:
            formatted_finding = {
                "component": self._extract_column_value(finding, 'component') or 'Unknown',
                "severity": self._extract_column_value(finding, 'severity') or 'Unknown',
                "title": self._extract_column_value(finding, 'title') or 'No description',
                "file_path": self._extract_column_value(finding, 'file') or '',
                "line_number": self._extract_column_value(finding, 'line') or '',
                "raw_data": finding
            }
            payload["findings"].append(formatted_finding)
        
        return json.dumps(payload, indent=2, ensure_ascii=False)
    
    def format_table(self, headers: List[str], rows: List[List[Any]], title: str = "Results") -> str:
        """Format tabular data as webhook payload.
        
        Args:
            headers: Column headers
            rows: Table rows as lists of values
            title: Title for the formatted table
            
        Returns:
            JSON payload suitable for webhook endpoints
        """
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "security_table_data",
            "title": title,
            "summary": {
                "total_rows": len(rows),
                "columns": headers
            },
            "data": []
        }
        
        # Convert rows to list of dictionaries
        for row in rows:
            row_dict = {}
            for i, header in enumerate(headers):
                value = self.sanitize_text(row[i]) if i < len(row) else ""
                row_dict[header] = value
            payload["data"].append(row_dict)
        
        return json.dumps(payload, indent=2, ensure_ascii=False)
    
    def _count_severities(self, findings: List[dict]) -> dict:
        """Count findings by severity level.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary with severity counts
        """
        severity_counts = {}
        for finding in findings:
            severity = self._extract_column_value(finding, 'severity') or 'Unknown'
            severity_lower = str(severity).lower()
            severity_counts[severity_lower] = severity_counts.get(severity_lower, 0) + 1
        
        return severity_counts