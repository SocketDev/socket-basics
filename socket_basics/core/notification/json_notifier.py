import json
import logging
from typing import Any, Dict, List

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class JsonNotifier(BaseNotifier):
    """Console JSON notifier: prints a compact notifications JSON to stdout.

    The notifier reads optional parameters from `self.config` (provided by manager).
    It also has `app_config` attached at runtime so it can consult global flags.
    """

    name = "json"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # optional output_path param (not used by default console behavior)
        self.output_path = self.config.get('output_path') or 'notifications.json'

    def notify(self, facts: Dict[str, Any]) -> None:
        # Check if we received pre-formatted data from connectors
        notifications = facts.get('notifications', [])
        if not notifications:
            logger.info('JsonNotifier: no notifications present in facts; skipping')
            return

        # New simplified format: list of {title, content} dicts
        if isinstance(notifications, list):
            valid_notifications = []
            for item in notifications:
                if isinstance(item, dict) and 'title' in item and 'content' in item:
                    valid_notifications.append(item)
                else:
                    logger.warning('JsonNotifier: skipping invalid notification item: %s', type(item))
            
            if valid_notifications:
                # Create structured JSON output with metadata
                json_output = {
                    'notifications': valid_notifications,
                    'metadata': {
                        'repository': facts.get('repository'),
                        'branch': facts.get('branch'),
                        'timestamp': facts.get('timestamp'),
                        'total_notifications': len(valid_notifications)
                    }
                }
                print(json.dumps(json_output, indent=2))
                return
            else:
                logger.info('JsonNotifier: no valid notifications found')
                print(json.dumps({'notifications': [], 'metadata': {'total_notifications': 0}}, indent=2))
                return
        else:
            logger.error('JsonNotifier: only supports new format - list of dicts with title/content')
            return
