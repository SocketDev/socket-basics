from typing import Any, Dict
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import (
    get_ms_sentinel_workspace_id, get_ms_sentinel_shared_key, 
    get_ms_sentinel_collector_url
)

logger = logging.getLogger(__name__)


class MSSentinelNotifier(BaseNotifier):
    """Microsoft Sentinel notifier: sends security findings to Sentinel HTTP Data Collector.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "ms_sentinel"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # MS Sentinel configuration from params, env variables, or app config
        self.workspace_id = (
            self.config.get('workspace_id') or
            get_ms_sentinel_workspace_id()
        )
        self.shared_key = (
            self.config.get('shared_key') or
            get_ms_sentinel_shared_key()
        )
        self.collector_url = (
            self.config.get('collector_url') or
            get_ms_sentinel_collector_url()
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('MSSentinelNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('MSSentinelNotifier: no notifications present; skipping')
            return

        # Get full scan URL if available
        full_scan_url = facts.get('full_scan_html_url')

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                # Append full scan URL to content if available
                content = item['content']
                if full_scan_url:
                    content += f"\n\nFull scan results: {full_scan_url}"
                    item = {'title': item['title'], 'content': content}
                valid_notifications.append(item)
            else:
                logger.warning('MSSentinelNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate Sentinel event
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            self._send_sentinel_event(facts, title, content)

    def _send_sentinel_event(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single event to Microsoft Sentinel with title and content."""
        if not all([self.workspace_id, self.shared_key]):
            logger.warning('MSSentinelNotifier: missing required configuration (workspace_id, shared_key)')
            return

        # Get repository and branch info from config (discovered by main logic)
        repo = self.config.get('repository', 'Unknown')
        branch = self.config.get('branch', 'Unknown')

        # Create Sentinel event payload with pre-formatted content
        event = {
            'TimeGenerated': facts.get('timestamp'),
            'Source': 'SocketSecurity',
            'Repository': repo,
            'Branch': branch,
            'Severity': 'High',
            'Title': title,
            'Content': content,
            'EventType': 'SecurityFinding'
        }

        try:
            if self.collector_url:
                # Use custom collector URL if provided
                import requests
                resp = requests.post(self.collector_url, json=[event], timeout=10)
                if resp.status_code >= 400:
                    logger.warning('MSSentinelNotifier: collector error %s: %s', resp.status_code, resp.text[:200])
                else:
                    logger.info('MSSentinelNotifier: sent event for "%s"', title)
            else:
                # Would need to implement Sentinel HTTP Data Collector API authentication here
                # For now, just log the event
                logger.info('MSSentinelNotifier: would send event for "%s" (collector URL not configured)', title)
                
        except Exception as e:
            logger.error('MSSentinelNotifier: exception sending event: %s', e)
