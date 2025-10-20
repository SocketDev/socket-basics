from typing import Any, Dict
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import get_webhook_url

logger = logging.getLogger(__name__)


class WebhookNotifier(BaseNotifier):
    """Webhook notifier: sends security findings to HTTP webhook endpoints.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "webhook"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # Webhook URL from params, env variable, or app config
        self.url = (
            self.config.get('url') or
            get_webhook_url()
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('WebhookNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('WebhookNotifier: no notifications present; skipping')
            return

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                valid_notifications.append(item)
            else:
                logger.warning('WebhookNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate webhook
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            self._send_webhook(facts, title, content)

    def _send_webhook(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single webhook with title and content."""
        if not self.url:
            logger.warning('WebhookNotifier: no webhook URL configured')
            return

        # Get repository and branch info from config (discovered by main logic)
        repo = self.config.get('repository', 'Unknown')
        branch = self.config.get('branch', 'Unknown')

        # Create webhook payload with pre-formatted content
        payload = {
            'repository': repo,
            'branch': branch,
            'scanner': 'socket-security',
            'timestamp': facts.get('timestamp'),
            'notification': {
                'title': title,
                'content': content
            }
        }

        try:
            import requests
            resp = requests.post(self.url, json=payload, timeout=10)
            if resp.status_code >= 400:
                logger.warning('WebhookNotifier: HTTP error %s: %s', resp.status_code, resp.text[:200])
            else:
                logger.info('WebhookNotifier: sent webhook for "%s"', title)
                
        except Exception as e:
            logger.error('WebhookNotifier: exception sending webhook: %s', e)
