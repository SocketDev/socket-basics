from typing import Any, Dict
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import get_msteams_webhook_url

logger = logging.getLogger(__name__)


class MSTeamsNotifier(BaseNotifier):
    """Microsoft Teams notifier: posts security findings to Teams webhook.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "msteams"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # Teams webhook URL from params, env variable, or app config
        self.webhook_url = (
            self.config.get('webhook_url') or
            get_msteams_webhook_url()
        )
        self.title = self.config.get('title', 'Socket Security')

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('MSTeamsNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('MSTeamsNotifier: no notifications present; skipping')
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
                    content += f"\n\n🔗 [View Full Socket Scan]({full_scan_url})"
                valid_notifications.append({'title': item['title'], 'content': content})
            else:
                logger.warning('MSTeamsNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate Teams message
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            self._send_teams_message(facts, title, content)

    def _send_teams_message(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single Teams message with title and content."""
        if not self.webhook_url:
            logger.warning('MSTeamsNotifier: no Teams webhook URL configured')
            return

        # Get repository and branch info from facts (populated by NotificationManager)
        repo = facts.get('repository', 'Unknown')
        branch = facts.get('branch', 'Unknown')

        try:
            # Create Teams MessageCard payload with pre-formatted content
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"Socket Security - {title}",
                "themeColor": "FF6B35",
                "title": f"🔍 Socket Security - {title}",
                "sections": [
                    {
                        "facts": [
                            {"name": "Repository", "value": repo},
                            {"name": "Branch", "value": branch}
                        ],
                        "markdown": True
                    },
                    {
                        "activityTitle": title,
                        "text": content,
                        "markdown": True
                    }
                ]
            }
            
            import requests
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code >= 400:
                logger.warning('MSTeamsNotifier: webhook error %s: %s', resp.status_code, resp.text[:200])
            else:
                logger.info('MSTeamsNotifier: posted message for "%s"', title)
                
        except Exception as e:
            logger.error('MSTeamsNotifier: exception posting message: %s', e)
