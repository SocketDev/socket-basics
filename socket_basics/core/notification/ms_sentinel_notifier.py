import json
import logging
import os
from typing import Any, Dict, List

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class MSSentinelNotifier(BaseNotifier):
    """Microsoft Sentinel notifier: builds compact JSON bodies suitable for ingestion
    by Sentinel HTTP Data Collector API. This follows JsonNotifier mapping style.
    """

    name = "ms_sentinel"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # read configuration from params or environment variables
        self.workspace_id = self.config.get('workspace_id') or os.getenv('INPUT_MS_SENTINEL_WORKSPACE_ID')
        self.shared_key = self.config.get('shared_key') or os.getenv('INPUT_MS_SENTINEL_SHARED_KEY')
        # collector_url optional override
        self.collector_url = self.config.get('collector_url') or os.getenv('INPUT_MS_SENTINEL_COLLECTOR_URL')

    def notify(self, facts: Dict[str, Any]) -> None:
        # Sentinel expects flattened event entries. Require new notification
        # contract and do not synthesize events from components.
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('MSSentinelNotifier: no notifications present in facts; skipping')
            return

        # Flatten groups into events list
        events: List[Dict[str, Any]] = []
        if isinstance(notifications, list):
            for grp in notifications:
                if not isinstance(grp, dict):
                    continue
                rows = grp.get('rows') or []
                headers = grp.get('headers') or []
                for r in rows:
                    # map row columns to known fields where possible
                    ev = {'repository': facts.get('repository'), 'branch': facts.get('branch')}
                    try:
                        # Best-effort mapping by header names
                        for i, h in enumerate(headers):
                            key = str(h).strip().lower()
                            ev[key] = r[i] if i < len(r) else None
                    except Exception:
                        pass
                    events.append(ev)
        elif isinstance(notifications, dict):
            for title, payload in notifications.items():
                if not isinstance(payload, dict):
                    continue
                headers = payload.get('headers') or []
                for r in payload.get('rows') or []:
                    ev = {'repository': facts.get('repository'), 'branch': facts.get('branch'), 'group': title}
                    try:
                        for i, h in enumerate(headers):
                            ev[str(h).strip().lower()] = r[i] if i < len(r) else None
                    except Exception:
                        pass
                    events.append(ev)

        body = {'repository': facts.get('repository'), 'branch': facts.get('branch'), 'events': events}

        # If configuration not provided, print JSON to stdout for debugging
        if not (self.workspace_id and self.shared_key):
            logger.info('Sentinel credentials not configured; printing payload to stdout')
            try:
                print(json.dumps(body, indent=2))
            except Exception:
                logger.debug('Failed to print sentinel payload to stdout')
            return

        try:
            import requests
            collector_url = self.config.get('collector_url') or self.collector_url
            if collector_url:
                resp = requests.post(collector_url, json=events)
                if resp.status_code >= 400:
                    logger.error('Sentinel collector returned %s: %s', resp.status_code, resp.text)
            else:
                try:
                    print(json.dumps(body, indent=2))
                except Exception:
                    logger.debug('Failed to print sentinel payload to stdout')
        except Exception:
            logger.exception('Failed to send to Sentinel')
