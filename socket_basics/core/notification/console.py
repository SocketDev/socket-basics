from typing import Any, Dict, List
import logging

from tabulate import tabulate
from socket_basics.core.notification.base import BaseNotifier

logger = logging.getLogger(__name__)


class ConsoleNotifier(BaseNotifier):
    name = "console"

    def _sanitize_cell(self, cell: Any) -> Any:
        """Normalize table cell values: shorten long strings and collapse newlines."""
        if not isinstance(cell, str):
            return str(cell) if cell is not None else ""
        
        # Truncate very long strings
        if len(cell) > 200:
            return cell[:197] + "..."
        
        # Replace newlines with spaces for table display
        return " ".join(cell.split())

    def notify(self, facts: Dict[str, Any]) -> None:
        # New simplified format: expect notifications to be a list of {title, content} dicts
        notifications = facts.get('notifications', []) or []
        
        if isinstance(notifications, list) and notifications:
            # Display each notification separately
            for item in notifications:
                if isinstance(item, dict) and 'title' in item and 'content' in item:
                    title = item['title']
                    content = item['content']
                    
                    print(f"\n{title.upper()}")
                    print("-" * len(title))
                    print(content)
                    print()
                else:
                    logger.warning("ConsoleNotifier: skipping invalid notification item: %s", type(item))
            return
        
        # No console data available
        logger.debug("No console notifications found")