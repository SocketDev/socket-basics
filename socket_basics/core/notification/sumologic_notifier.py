import json
import logging
import os
from typing import Any, Dict, List

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class SumoLogicNotifier(BaseNotifier):
    """Sumo Logic notifier: emits compact JSON or will send to HTTP source if configured.
    Follows JsonNotifier grouping shape for `notifications`.
    """

    name = "sumologic"

    def __init__(self, params: Dict[str, Any] | None = None):
        """Initialize SumoLogicNotifier with optional config params.

        Params may include 'http_source_url'. Falls back to INPUT_SUMO_LOGIC_HTTP_SOURCE_URL.
        """
        super().__init__(params or {})
        # read configuration from params or environment variables
        self.http_source_url = self.config.get('http_source_url') or os.getenv('INPUT_SUMO_LOGIC_HTTP_SOURCE_URL')

    def notify(self, facts: Dict[str, Any]) -> None:
        # Strict: use only canonical notifications attached to facts. Do not
        # synthesize from components. If no notifications present, skip.
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('SumoLogicNotifier: no notifications present in facts; skipping')
            return

        # Normalize and validate groups: ensure at least one group has headers and rows
        groups: List[Dict[str, Any]] = []
        if isinstance(notifications, list):
            for item in notifications:
                if not isinstance(item, dict):
                    continue
                groups.append({'title': item.get('title') or 'results', 'headers': item.get('headers'), 'rows': item.get('rows') or []})
        elif isinstance(notifications, dict):
            for title, payload in notifications.items():
                if isinstance(payload, dict):
                    groups.append({'title': title, 'headers': payload.get('headers'), 'rows': payload.get('rows') or []})
                elif isinstance(payload, list):
                    groups.append({'title': title, 'headers': None, 'rows': payload})

        valid = any(isinstance(g.get('headers'), list) and isinstance(g.get('rows'), list) for g in groups)
        if not valid:
            logger.info('SumoLogicNotifier: notifications present but none match required {headers:list, rows:list} shape; skipping')
            return

        body = {'repository': facts.get('repository'), 'branch': facts.get('branch'), 'notifications': groups}

        if not self.http_source_url:
            logger.info('Sumo Logic HTTP source not configured; printing payload to stdout')
            try:
                print(json.dumps(body, indent=2))
            except Exception:
                logger.debug('Failed to print Sumo Logic payload to stdout')
            return

        try:
            import requests
            resp = requests.post(self.http_source_url, json=body)
            if resp.status_code >= 400:
                logger.error('Sumo Logic returned %s: %s', resp.status_code, resp.text)
        except Exception:
            logger.exception('Failed to send to Sumo Logic')
