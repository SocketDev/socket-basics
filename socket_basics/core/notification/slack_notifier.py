from typing import Any, Dict
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import get_slack_webhook_url, get_github_repository

logger = logging.getLogger(__name__)


class SlackNotifier(BaseNotifier):
    """Slack notifier: posts security findings to Slack webhook.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "slack"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # Slack webhook URL from params, env variable, or app config
        self.webhook_url = (
            self.config.get('webhook_url') or
            get_slack_webhook_url()
        )
        self.username = "Socket Security"
        
        # Get repository from config or environment
        self.repository = (
            self.config.get('repository') or
            get_github_repository() or
            'Unknown'
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('SlackNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('SlackNotifier: no notifications present; skipping')
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
                    content += f"\n\n🔗 <{full_scan_url}|View complete scan results>"
                    item = {'title': item['title'], 'content': content}
                valid_notifications.append(item)
            else:
                logger.warning('SlackNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate Slack message
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            self._send_slack_message(facts, title, content)

    def _send_slack_message(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single Slack message with title and content."""
        if not self.webhook_url:
            logger.warning('SlackNotifier: no Slack webhook URL configured')
            return

        # Get repository and branch info from config (discovered by main logic)
        repo = self.repository
        branch = self.config.get('branch', 'Unknown')

        try:
            # Truncate content if too long for Slack (3000 char limit per text block)
            max_content_length = 2500  # Leave room for title and formatting
            if len(content) > max_content_length:
                content = content[:max_content_length] + "...\n[Content truncated]"
            
            # Create Slack payload with pre-formatted content
            payload = {
                "username": self.username,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"🔍 *Security Findings* - {repo} ({branch})"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{title}*\n```\n{content}\n```"
                        }
                    }
                ]
            }
            
            import requests
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code >= 400:
                logger.warning('SlackNotifier: webhook error %s: %s', resp.status_code, resp.text[:200])
            else:
                logger.info('SlackNotifier: posted message for "%s"', title)
                
        except Exception as e:
            logger.error('SlackNotifier: exception posting message: %s', e)
