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

        # Validate format and store URL separately for block building
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                # Store original content and URL separately so we can add URL as its own block
                valid_notifications.append({
                    'title': item['title'], 
                    'content': item['content'],
                    'full_scan_url': full_scan_url
                })
            else:
                logger.warning('SlackNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Send each notification as a separate Slack message
        for item in valid_notifications:
            title = item['title']
            content = item['content']
            full_scan_url = item.get('full_scan_url')
            self._send_slack_message(facts, title, content, full_scan_url)

    def _send_slack_message(self, facts: Dict[str, Any], title: str, content: str, full_scan_url: str | None = None) -> None:
        """Send a single Slack message with title and content."""
        if not self.webhook_url:
            logger.warning('SlackNotifier: no Slack webhook URL configured')
            return

        # Get repository and branch info from config (discovered by main logic)
        repo = self.repository
        branch = self.config.get('branch', 'Unknown')

        try:
            # Truncate content if it's too long for a single Slack block (3000 char limit)
            max_content_length = 2900  # Leave room for title and formatting
            if len(content) > max_content_length:
                content = content[:max_content_length] + "\n\n_(content truncated)_"
            
            # Create Slack payload with pre-formatted content
            blocks = [
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
                        "text": f"*{title}*\n\n{content}"
                    }
                }
            ]
            
            # Add full scan URL as a separate context block if available
            if full_scan_url:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🔗 <{full_scan_url}|View Full Socket Scan>"
                    }
                })
            
            payload = {
                "username": self.username,
                "blocks": blocks
            }
            
            import requests
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code >= 400:
                logger.warning('SlackNotifier: webhook error %s: %s', resp.status_code, resp.text[:500])
                logger.debug(f'Failed Slack payload: {payload}')
            else:
                logger.info('SlackNotifier: posted message for "%s"', title)
                
        except Exception as e:
            logger.error('SlackNotifier: exception posting message: %s', e)
