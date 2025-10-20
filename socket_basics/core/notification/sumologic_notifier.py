from typing import Any, Dict
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import get_sumologic_http_source_url

logger = logging.getLogger(__name__)


class SumoLogicNotifier(BaseNotifier):
    """SumoLogic notifier: sends security findings to SumoLogic HTTP collector.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "sumologic"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # SumoLogic HTTP source URL from params, env variable, or app config
        self.http_source_url = (
            self.config.get('http_source_url') or
            get_sumologic_http_source_url()
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('SumoLogicNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('SumoLogicNotifier: no notifications present; skipping')
            return

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                valid_notifications.append(item)
            else:
                logger.warning('SumoLogicNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate log entry
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            self._send_sumologic_log(facts, title, content)

    def _send_sumologic_log(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single log entry to SumoLogic with title and content."""
        if not self.http_source_url:
            logger.warning('SumoLogicNotifier: no HTTP source URL configured')
            return

        # Get repository and branch info from config (discovered by main logic)
        repo = self.config.get('repository', 'Unknown')
        branch = self.config.get('branch', 'Unknown')
        
        # Add full scan URL if available
        full_scan_url = facts.get('full_scan_url')
        if full_scan_url:
            content += f"\n\nfull_scan_url={full_scan_url}"

        # Create SumoLogic log payload with pre-formatted content
        log_entry = {
            'timestamp': facts.get('timestamp'),
            'source': 'socket-security',
            'repository': repo,
            'branch': branch,
            'severity': 'high',
            'title': title,
            'content': content
        }

        try:
            import requests
            resp = requests.post(self.http_source_url, json=log_entry, timeout=10)
            if resp.status_code >= 400:
                logger.warning('SumoLogicNotifier: HTTP error %s: %s', resp.status_code, resp.text[:200])
            else:
                logger.info('SumoLogicNotifier: sent log entry for "%s"', title)
                
        except Exception as e:
            logger.error('SumoLogicNotifier: exception sending log: %s', e)
