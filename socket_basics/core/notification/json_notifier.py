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
        # Strict: Expect NotificationManager to attach grouped `notifications`
        # to `facts` following the new contract. Accept either a list of table
        # dicts or a mapping of title -> {headers, rows}. Do not synthesize from
        # components or perform any legacy fallbacks.
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('JsonNotifier: no notifications present in facts; skipping')
            return

        # Normalize into canonical JSON to print. Accept list or dict, but
        # validate groups contain headers and rows per new contract.
        def _normalize(n: Any) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            if isinstance(n, list):
                for item in n:
                    if not isinstance(item, dict):
                        continue
                    title = item.get('title') or 'results'
                    headers = item.get('headers')
                    rows = item.get('rows') if item.get('rows') is not None else []
                    out.append({'title': title, 'headers': headers, 'rows': rows})
            elif isinstance(n, dict):
                for title, payload in n.items():
                    if isinstance(payload, dict):
                        headers = payload.get('headers')
                        rows = payload.get('rows') if payload.get('rows') is not None else []
                        out.append({'title': title, 'headers': headers, 'rows': rows})
                    elif isinstance(payload, list):
                        out.append({'title': title, 'headers': None, 'rows': payload})
            return out

        try:
            canonical = _normalize(notifications)
            # Enforce presence of at least one group with headers and rows. This
            # enforces the new contract; callers must produce validated tables.
            valid = any(isinstance(g.get('headers'), list) and isinstance(g.get('rows'), list) for g in canonical)
            if not valid:
                logger.info('JsonNotifier: notifications present but none match required {headers:list, rows:list} shape; skipping')
                return

            output = json.dumps({'notifications': canonical}, indent=2)
            # If an output_path is provided in params, write to that file instead of stdout
            if self.output_path and self.output_path != '-':
                try:
                    with open(self.output_path, 'w', encoding='utf-8') as f:
                        f.write(output)
                    logger.info('Wrote notifications JSON to %s', self.output_path)
                except Exception:
                    logger.exception('Failed to write notifications JSON to %s', self.output_path)
            else:
                # Default: print to stdout
                print(output)
                logger.info('Printed notifications JSON to stdout')
        except Exception as e:
            logger.exception('Failed to print notifications JSON: %s', e)
