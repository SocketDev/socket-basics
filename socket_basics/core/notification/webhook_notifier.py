import json
import logging
import os
from typing import Any, Dict

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class WebhookNotifier(BaseNotifier):
    """Webhook notifier: emits a structured JSON body similar to JsonNotifier
    for posting to arbitrary HTTP webhook endpoints.
    """

    name = "webhook"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # read configuration from params or environment variables
        self.url = self.config.get('url') or os.getenv('INPUT_WEBHOOK_URL')

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('WebhookNotifier: no notifications present in facts; skipping')
            return

        # Normalize groups into canonical list for downstream consumers
        groups = []
        if isinstance(notifications, list):
            for g in notifications:
                if not isinstance(g, dict):
                    continue
                groups.append({'title': g.get('title') or 'results', 'headers': g.get('headers'), 'rows': g.get('rows') or []})
        elif isinstance(notifications, dict):
            for title, payload in notifications.items():
                if isinstance(payload, dict):
                    groups.append({'title': title, 'headers': payload.get('headers'), 'rows': payload.get('rows') or []})
                elif isinstance(payload, list):
                    groups.append({'title': title, 'headers': None, 'rows': payload})

        valid = any(isinstance(g.get('headers'), list) and isinstance(g.get('rows'), list) for g in groups)
        if not valid:
            logger.info('WebhookNotifier: notifications present but none match required {headers:list, rows:list} shape; skipping')
            return

        body = {'repository': facts.get('repository'), 'branch': facts.get('branch'), 'notifications': groups}

        if not self.url:
            logger.info('Webhook notifier target URL not configured; printing body to stdout')
            try:
                print(json.dumps(body, indent=2))
            except Exception:
                logger.debug('Failed to print webhook body to stdout')
            return

        try:
            import requests
            resp = requests.post(self.url, json=body)
            if resp.status_code >= 400:
                logger.error('Webhook target returned %s: %s', resp.status_code, resp.text)
        except Exception:
            logger.exception('Failed to post to webhook target')
