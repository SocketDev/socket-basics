from typing import Any, Dict, List
import logging

from tabulate import tabulate
from socket_basics.core.notification.base import BaseNotifier

logger = logging.getLogger(__name__)


class ConsoleNotifier(BaseNotifier):
    name = "console"

    def _preview_snippet(self, text: str, max_lines: int = 2, max_chars: int = 140) -> str:
        """Return a compact single-line preview for potentially multi-line snippets.

        - Collapse consecutive whitespace and newlines.
        - Join up to `max_lines` with a visible separator and append ellipsis if truncated.
        - Truncate to `max_chars` characters with ellipsis.
        """
        if not isinstance(text, str) or not text:
            return text or ""

        # Split into logical lines and trim
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            return ""

        preview_lines = lines[:max_lines]
        preview = " ⏎ ".join(preview_lines)
        if len(lines) > max_lines:
            preview = preview + " ⏎ ..."

        # Collapse repeated whitespace inside the preview
        preview = " ".join(preview.split())

        if len(preview) > max_chars:
            return preview[: max_chars - 3] + "..."
        return preview

    def _sanitize_cell(self, cell: Any) -> Any:
        """Normalize table cell values: shorten long strings and collapse newlines."""
        # If connector provided a raw match-group structure (list of frames),
        # try to convert it into a human-readable nested arrow string using
        # the SocketTier1Scanner formatter. This is defensive: some connectors
        # historically returned structured objects which tabulate would print
        # as raw Python reprs.
        if not isinstance(cell, str) and isinstance(cell, list):
            try:
                # local import to avoid circular module-level dependencies
                from socket_basics.core.connector.socket_tier1.scanner import SocketTier1Scanner

                formatted = SocketTier1Scanner(config=None)._format_match_groups(cell)
                if formatted:
                    cell = "```\n" + formatted + "\n```"
                else:
                    cell = str(cell)
            except Exception:
                # Fall back to stringifying the cell
                try:
                    cell = str(cell)
                except Exception:
                    pass

        if isinstance(cell, str):
            # If it contains newlines or is long, create a preview
            if "\n" in cell or len(cell) > 200:
                return self._preview_snippet(cell)
            # Otherwise collapse excessive internal whitespace
            return " ".join(cell.split())
        return cell

    def _format_location(self, loc: Dict[str, Any]) -> str:
        if not loc:
            return "-"
        path = loc.get("path", "-")
        line = loc.get("line")
        if line is not None:
            return f"{path}:{line}"
        return path

    def notify(self, facts: Dict[str, Any]) -> None:
        components = facts.get("components", [])

        # Diagnostic: log the notifications payload to help debug why console
        # might be falling back to the 'ALL FINDINGS' table.
        try:
            notif_payload = facts.get('notifications')
            if notif_payload is not None:
                try:
                    # keep debug concise
                    logger_payload = {k: (type(v).__name__) for k, v in (notif_payload.items() if isinstance(notif_payload, dict) else [])}
                except Exception:
                    logger_payload = str(type(notif_payload))
                try:
                    import logging

                    logging.getLogger(__name__).debug('ConsoleNotifier received facts.notifications: %s', logger_payload)
                except Exception:
                    pass
        except Exception:
            pass

        # Console notifier should not decide which severities to show; the
        # NotificationManager is responsible for filtering notifications by
        # severity. Notifier only formats and presents whatever is attached
        # to `facts['notifications']` or raw `facts['components']`.

        # If global consolidated console output is enabled, show a single table for all components
        consolidated = False
        try:
            app_cfg = getattr(self, 'app_config', {}) or {}
            # Only enable consolidated tabular output when console_tabular_enabled is explicitly set
            consolidated = bool(app_cfg.get('console_tabular_enabled'))
        except Exception:
            consolidated = False

        # Only show tabular consolidated output when explicitly requested
        if consolidated:
            # If connectors provided pre-built notification rows, use them per category
            notifications = facts.get('notifications', {}) or {}

            # mapping of connector -> (display name, headers) (reserved for future use)
            categories = {
                'opengrep': ('SAST', ['Rule', 'File', 'Location', 'Lines', 'Snippet']),
                'trufflehog': ('Secret Scanning', ['Detector', 'Severity', 'File', 'Line', 'Redacted']),
                'trivy': ('Image/Dockerfile', ['Title', 'Severity', 'Image', 'Package'])
            }

            printed_any = False

            # If the connector produced socket_tier1 data, prefer the
            # connector-provided notifications when present. Connectors may
            # now supply the canonical list-of-table-dicts format or the older
            # dict-mapping format. Normalize either into an internal mapping
            # of {title -> {headers, rows}} for consistent processing below.
            provided = facts.get('notifications', {}) or {}

            # Normalize list-of-table-dicts into mapping {title: {headers, rows}}
            normalized: Dict[str, Dict[str, Any]] = {}
            try:
                if isinstance(provided, dict):
                    normalized = provided
                elif isinstance(provided, list):
                    for item in provided:
                        if not isinstance(item, dict):
                            continue
                        title = item.get('title') or 'results'
                        headers = item.get('headers')
                        rows = item.get('rows') or []
                        normalized.setdefault(title, {'headers': headers, 'rows': []})
                        if rows:
                            normalized[title]['rows'].extend(rows)
            except Exception:
                normalized = provided if isinstance(provided, dict) else {}

            if 'socket_tier1' in facts:
                # Prefer the connector-provided normalized payload when present
                if normalized.get('Socket Tier 1 Reachability'):
                    notifications = normalized
                else:
                    try:
                        from socket_basics.core.connector.socket_tier1.scanner import SocketTier1Scanner
                        rows_from_scanner = SocketTier1Scanner(config=None).notification_rows(facts)
                        if rows_from_scanner:
                            # rows_from_scanner expected to be list of table dicts
                            for item in rows_from_scanner:
                                if isinstance(item, dict) and 'title' in item and 'rows' in item:
                                    title = item.get('title')
                                    headers = item.get('headers')
                                    rows = item.get('rows') or []
                                    normalized.setdefault(title, {'headers': headers, 'rows': []})
                                    normalized[title]['rows'].extend(rows)
                            notifications = normalized
                        else:
                            notifications = normalized or {}
                    except Exception:
                        notifications = normalized or {}
            else:
                notifications = normalized or {}

            # Iterate and print all notification groups (connector-provided or otherwise)
            for group_label, payload in (notifications.items() if isinstance(notifications, dict) else []):
                if not payload:
                    continue
                # payload must be dict with 'headers' and 'rows' per Manager contract
                if not isinstance(payload, dict) or 'rows' not in payload:
                    logger.warning('ConsoleNotifier: skipping notification group %s due to unexpected payload shape', group_label)
                    continue
                headers = payload.get('headers')
                rows = payload.get('rows') or []

                # Require connector-provided headers; do not infer or override
                if not headers or not isinstance(headers, list):
                    logger.warning('ConsoleNotifier: skipping notification group %s because headers missing or invalid; Manager should filter these', group_label)
                    continue

                display = group_label
                display_headers = headers

                # Sanitize rows for printing
                sanitized_input_rows = []
                for r in rows:
                    # If headers indicate SAST-like shape or group label suggests SAST,
                    # try to map common legacy shapes into a reasonable presentation.
                    sanitized_input_rows.append(r if isinstance(r, (list, tuple)) else [str(r)])

                sanitized_rows = [[self._sanitize_cell(cell) for cell in row] for row in sanitized_input_rows]
                print(display.upper())
                print(tabulate(sanitized_rows, headers=display_headers, tablefmt='github'))
                print()
                printed_any = True

            if printed_any:
                return

            # If `facts['notifications']` existed but was empty (no groups), do not
            # fall back to printing ALL FINDINGS; this likely indicates connectors
            # intentionally suppressed notifications for current severity filter.
            if notif_payload is not None and (not normalized):
                # Nothing to print and notifications were intentionally empty
                return

            # If no connector-specific rows were provided, fallback to grouped tables by inferred tool
            rows: List[List[str]] = []
            for c in components:
                comp_name = c.get('name') or c.get('id') or '-'
                for a in c.get('alerts', []):
                    path = comp_name or a.get('location', {}).get('path', '-')
                    sev = a.get('severity', '')
                    msg = a.get('message') or a.get('title') or a.get('description', '')
                    loc_str = self._format_location(a.get('location', {}) or {})
                    rows.append([path, sev, self._sanitize_cell(msg), loc_str])

            if rows:
                print("ALL FINDINGS")
                print(tabulate(rows, headers=["File", "Severity", "Message", "Location"], tablefmt="github"))
                return

        # summary
        total_components = len(components)
        total_alerts = 0
        per_type: Dict[str, int] = {}
        for c in components:
            alerts = c.get("alerts", [])
            total_alerts += len(alerts)
            for a in alerts:
                # Prefer connector qualifier or alert props.tool over the generic alert type
                t = (
                    c.get('qualifiers', {}).get('scanner') or
                    a.get('props', {}).get('tool') or
                    a.get('type', 'unknown')
                )
                per_type[t] = per_type.get(t, 0) + 1

        print("Socket Basics Scan Summary")
        print("--------------------------")
        print(f"Components: {total_components}")
        print(f"Total alerts: {total_alerts}")
        for t, cnt in per_type.items():
            print(f" - {t}: {cnt}")
        print()

        # Group by connector/tool using component qualifiers or alert props when available
        grouped: Dict[str, List[List[str]]] = {}
        for c in components:
            # Determine logical tool/scanner name
            # Prefer explicit qualifiers (scanner) when present so components typed as 'generic'
            # but qualified as sast/secrets/dockerfile/image are grouped correctly.
            tool = (c.get('qualifiers', {}) or {}).get('scanner') or c.get('tool') or c.get('source') or c.get('name') or 'unknown'
            # Note: above uses qualifiers first. We'll fallback per-alert if needed.
            alerts = c.get('alerts', [])
            for a in alerts:
                # Per-alert override if component-level scanner missing
                alert_tool = (
                    c.get('qualifiers', {}).get('scanner') or
                    a.get('props', {}).get('tool') or
                    a.get('type') or
                    c.get('type') or
                    c.get('name') or
                    'unknown'
                )
                path = c.get('name') or a.get('location', {}).get('path', "-")
                sev = a.get('severity', '')
                # Prefer title/description/message
                msg = a.get('message') or a.get('title') or a.get('description', '')
                loc_str = self._format_location(a.get('location', {}) or {})
                grouped.setdefault(alert_tool, []).append([path, sev, self._sanitize_cell(msg), loc_str])

        # Friendly display mapping for known scanner keys
        display_map = {
            'sast': 'SAST',
            'secret': 'SECRET SCANNING',
            'secrets': 'SECRET SCANNING',
            'trufflehog': 'SECRET SCANNING',
            'trivy': 'IMAGE/DOCKERFILE',
            'dockerfile': 'DOCKERFILE',
            'image': 'IMAGE'
        }

        for tool_key in sorted(grouped.keys()):
            rows = grouped[tool_key]
            if not rows:
                continue
            display = display_map.get(str(tool_key).lower(), str(tool_key).upper())
            print(display)
            print(tabulate(rows, headers=["File", "Severity", "Message", "Location"], tablefmt="github"))
            print()
