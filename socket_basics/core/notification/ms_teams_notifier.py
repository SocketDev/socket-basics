import json
import logging
import os
import subprocess
from typing import Any, Dict, List

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class MSTeamsNotifier(BaseNotifier):
    """Microsoft Teams notifier using incoming webhook connectors.

    This follows the same pattern as SlackNotifier: it reads a webhook URL from
    params or environment variables and posts grouped notifications (produced
    by NotificationManager) as a simple card payload compatible with Teams
    incoming webhooks.
    """

    name = "msteams"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        self.webhook_url = (
            self.config.get('webhook_url')
            or os.getenv('MSTEAMS_WEBHOOK_URL')
            or os.getenv('INPUT_MSTEAMS_WEBHOOK_URL')
        )
        self.enabled = True if self.webhook_url else False
        self.title = self.config.get('title') or 'Socket Security'

    def _derive_repo_branch(self, facts: Dict[str, Any]) -> tuple[str | None, str | None]:
        repo = facts.get('repository') or os.getenv('GITHUB_REPOSITORY')
        branch = facts.get('branch') or os.getenv('GITHUB_REF')
        if branch and branch.startswith('refs/heads/'):
            branch = branch.split('refs/heads/')[-1]

        if not branch:
            try:
                branch = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], text=True).strip()
            except Exception:
                branch = None

        if not repo:
            try:
                url = subprocess.check_output(['git', 'config', '--get', 'remote.origin.url'], text=True).strip()
                if url.endswith('.git'):
                    url = url[:-4]
                if url.startswith('git@'):
                    repo = url.split(':', 1)[1]
                else:
                    parts = url.rstrip('/').split('/')
                    if len(parts) >= 2:
                        repo = f"{parts[-2]}/{parts[-1]}"
                    else:
                        repo = url
            except Exception:
                repo = None

        return repo, branch

    def notify(self, facts: Dict[str, Any]) -> None:
        # Require canonical notifications provided by NotificationManager.
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('MSTeamsNotifier: no notifications present in facts; skipping')
            return

        # Normalize groups into canonical list form and validate headers/rows
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
            logger.info('MSTeamsNotifier: notifications present but none match required {headers:list, rows:list} shape; skipping')
            return

        repo, branch = self._derive_repo_branch(facts)
        repo_display = repo or (facts.get('workspace') or os.getenv('GITHUB_WORKSPACE') or 'unknown')
        branch_display = branch or 'unknown'

        total = sum(len(g.get('rows') or []) for g in groups)

        # Build visually-pleasing MessageCard sections
        sections: List[Dict[str, Any]] = []
        # Add a facts-style summary section with repo/branch/total
        facts_list = [
            {"name": "Repository", "value": str(repo_display)},
            {"name": "Branch", "value": str(branch_display)},
            {"name": "Total Alerts", "value": str(total)},
        ]

        # Compose the card title and summary derived from repo/branch/total
        derived_title = f"Socket Security  {repo_display}  branch {branch_display}  {total} alert(s)"

        # Build group sections with short, readable lines
        for g in groups:
            group_label = g.get('title')
            rows = g.get('rows') or []
            if not rows:
                continue
            text_lines: List[str] = []
            # Show up to 10 items per group for brevity
            for r in rows[:10]:
                if isinstance(r, (list, tuple)) and len(r) >= 4:
                    rule = r[0]
                    file = r[1]
                    loc = r[2]
                    lines = r[3]
                    text_lines.append(f"\u2022 {rule} \u2014 {file}:{loc} (lines: {lines})")
                else:
                    # fallback to stringified row
                    text_lines.append(f"\u2022 {str(r)}")

            sections.append({
                "activityTitle": group_label,
                "text": "\n".join(text_lines),
            })

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": derived_title,
            "themeColor": "0078D7",
            "title": derived_title,
            "sections": [{"facts": facts_list, "markdown": True}] + sections,
        }

        url = self.webhook_url or getattr(self, 'app_config', {}).get('msteams_webhook_url')
        if not url:
            logger.info('MS Teams webhook URL not configured; skipping notification')
            return

        try:
            import requests

            resp = requests.post(url, json=payload)
            if resp.status_code >= 400:
                logger.error('MS Teams webhook error %s: %s', resp.status_code, resp.text)
        except Exception:
            logger.exception('Failed to send MS Teams notification')
