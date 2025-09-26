import json
import logging
import os
import subprocess
from typing import Any, Dict, List

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class SlackNotifier(BaseNotifier):
    """Slack notifier that prefers grouped notifications (from NotificationManager)
    and renders them into Slack Block Kit payloads for incoming webhooks.
    """

    name = "slack"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # read configuration from params or environment variables
        # prefer uppercase SLACK_* env vars; fall back to INPUT_* names for compatibility
        self.webhook_url = (
            self.config.get('webhook_url')
            or os.getenv('SLACK_WEBHOOK_URL')
            or os.getenv('INPUT_SLACK_WEBHOOK_URL')
        )
        # previously supported an explicit enabled flag; posting now depends solely on presence of webhook URL
        self.enabled = True if self.webhook_url else False
        # fixed username label
        self.username = "Socket Security"

    def notify(self, facts: Dict[str, Any]) -> None:
        # Normalize canonical notifications shape: list of tables -> mapping title -> {'headers','rows'}
        raw_notifications = facts.get('notifications') or {}
        notifications: Dict[str, Dict[str, Any]] = {}
        if isinstance(raw_notifications, list):
            for t in raw_notifications:
                try:
                    title = t.get('title') or 'results'
                    headers = t.get('headers')
                    rows = t.get('rows') or []
                    notifications[title] = {'headers': headers, 'rows': rows}
                except Exception:
                    continue
        elif isinstance(raw_notifications, dict):
            for title, payload in raw_notifications.items():
                try:
                    if isinstance(payload, dict):
                        headers = payload.get('headers')
                        rows = payload.get('rows') or []
                        notifications[title] = {'headers': headers, 'rows': rows}
                    elif isinstance(payload, list):
                        # legacy mapping of title -> rows (no headers); skip per-manager contract
                        logger.warning('SlackNotifier: legacy notification mapping received for %s without headers; skipping', title)
                    else:
                        logger.warning('SlackNotifier: unexpected payload type for %s: %s; skipping', title, type(payload))
                except Exception:
                    continue

        if not notifications:
            logger.debug('No grouped notifications available for Slack')
            return

        # Build Slack blocks using native Block Kit fields for better readability
        blocks: List[Dict[str, Any]] = []
        total = sum(len(v) for v in notifications.values())

        # Attempt to derive repository and branch from facts, env, or git
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
                    # git@github.com:owner/repo
                    repo = url.split(':', 1)[1]
                else:
                    parts = url.rstrip('/').split('/')
                    if len(parts) >= 2:
                        repo = f"{parts[-2]}/{parts[-1]}"
                    else:
                        repo = url
            except Exception:
                repo = None

        # Prefer the workspace name when repo is not available
        repo_display = repo
        if not repo_display:
            # facts may include workspace path; prefer a final path component as name
            workspace = facts.get('workspace') or os.getenv('GITHUB_WORKSPACE')
            if workspace:
                try:
                    from pathlib import Path

                    repo_display = Path(workspace).name
                except Exception:
                    repo_display = str(workspace)
            else:
                repo_display = 'unknown'
        branch_display = branch or 'unknown'

        header_section = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Socket Security* — *{repo_display}* — branch `{branch_display}` — *{total} alert(s)*"
            }
        }
        blocks.append(header_section)
        blocks.append({"type": "divider"})

        for group_label, payload in notifications.items():
            headers = payload.get('headers')
            rows = payload.get('rows') or []
            # Strict: use only connector-provided headers. Skip groups without valid headers.
            if not headers or not isinstance(headers, list):
                logger.warning('SlackNotifier: skipping notification group %s because headers missing or invalid; Manager should filter these', group_label)
                continue
            if not rows:
                continue
            # Add a header for the group
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{group_label}*"}})

            # helper to find header index by name (case-insensitive)
            def hidx(name: str):
                try:
                    for i, h in enumerate(headers):
                        if isinstance(h, str) and h.strip().lower() == name.lower():
                            return i
                except Exception:
                    pass
                return None

            # Render up to 10 alerts per group as individual section blocks with fields
            for r in rows[:10]:
                fields = []
                snippet = ''
                # SAST rendering: prefer header indices if present
                if group_label.lower().startswith('sast'):
                    rule_i = hidx('rule')
                    file_i = hidx('file') or hidx('path')
                    loc_i = hidx('path') or hidx('location')
                    lines_i = hidx('lines')
                    code_i = hidx('code')

                    rule = r[rule_i] if rule_i is not None and rule_i < len(r) else (r[0] if len(r) > 0 else '')
                    file = r[file_i] if file_i is not None and file_i < len(r) else (r[2] if len(r) > 2 else '')
                    loc = r[loc_i] if loc_i is not None and loc_i < len(r) else (r[3] if len(r) > 3 else '')
                    lines = r[lines_i] if lines_i is not None and lines_i < len(r) else (r[4] if len(r) > 4 else '')
                    snippet = str(r[code_i]) if code_i is not None and code_i < len(r) else ''

                    fields = [
                        {"type": "mrkdwn", "text": f"*Rule:*\n{rule}"},
                        {"type": "mrkdwn", "text": f"*File:*\n{file}"},
                        {"type": "mrkdwn", "text": f"*Location:*\n{loc}"},
                        {"type": "mrkdwn", "text": f"*Lines:*\n{lines}"}
                    ]
                else:
                    # Generic rendering: prefer 'file' or 'title' and 'severity' headers
                    title_i = hidx('title') or hidx('rule') or 0
                    sev_i = hidx('severity')
                    loc_i = hidx('locator') or hidx('path') or hidx('location')
                    extra_i = hidx('location') or hidx('details') or None

                    title_val = r[title_i] if title_i is not None and title_i < len(r) else (r[0] if len(r) > 0 else '')
                    sev_val = r[sev_i] if sev_i is not None and sev_i < len(r) else (r[1] if len(r) > 1 else '')
                    loc_val = r[loc_i] if loc_i is not None and loc_i < len(r) else (r[2] if len(r) > 2 else '')
                    details_val = r[extra_i] if extra_i is not None and extra_i < len(r) else (r[3] if len(r) > 3 else '')

                    fields = [
                        {"type": "mrkdwn", "text": f"*Title:*\n{title_val}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{sev_val}"},
                        {"type": "mrkdwn", "text": f"*Locator:*\n{loc_val}"},
                        {"type": "mrkdwn", "text": f"*Details:*\n{details_val}"}
                    ]
                    snippet = ''

                blocks.append({"type": "section", "fields": fields})
                if snippet:
                    sn = snippet if len(snippet) <= 400 else snippet[:400] + '...'
                    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"```{sn}```"}]})

            blocks.append({"type": "divider"})

        payload = {"username": self.username, "blocks": blocks}

        # Post only if webhook_url provided in params or app_config
        url = self.webhook_url or getattr(self, 'app_config', {}).get('slack_webhook_url')
        if not url:
            # If no webhook configured, skip posting and do not print payload to stdout.
            logger.info("Slack webhook URL not configured; skipping Slack notification")
            return

        # Sanitize payload to avoid invalid_blocks errors from Slack.
        # Ensure all text fields are strings and truncate very long snippets.
        def _ensure_str(s: Any, max_len: int = 1000) -> str:
            try:
                if s is None:
                    return ''
                t = str(s)
                if len(t) > max_len:
                    return t[:max_len] + '...'
                return t
            except Exception:
                return ''
        try:
            # Slack Block Kit limits and safe truncation parameters
            MAX_BLOCKS = 45
            MAX_FIELDS_PER_SECTION = 10
            MAX_TEXT_CHARS = 3000
            MAX_CONTEXT_ELEMS = 10

            blocks = payload.get('blocks', []) or []
            sanitized_blocks: List[Dict[str, Any]] = []
            omitted = 0

            for b in blocks:
                if not isinstance(b, dict):
                    continue
                bt = b.get('type')
                nb: Dict[str, Any] = {'type': bt}

                # Section blocks: sanitize 'text' and 'fields'
                if bt == 'section':
                    text_obj = b.get('text')
                    if isinstance(text_obj, dict):
                        nb['text'] = {'type': text_obj.get('type', 'mrkdwn'), 'text': _ensure_str(text_obj.get('text', ''), MAX_TEXT_CHARS)}
                    # fields: ensure list of mrkdwn text objects, cap at MAX_FIELDS_PER_SECTION
                    flds = b.get('fields') or []
                    if isinstance(flds, list) and flds:
                        new_fields = []
                        for f in flds[:MAX_FIELDS_PER_SECTION]:
                            if isinstance(f, dict):
                                txt = f.get('text') if 'text' in f else ''
                                new_fields.append({'type': 'mrkdwn', 'text': _ensure_str(txt, 1000)})
                            else:
                                new_fields.append({'type': 'mrkdwn', 'text': _ensure_str(f, 1000)})
                        nb['fields'] = new_fields

                # Context blocks: sanitize elements and cap
                elif bt == 'context':
                    elems = b.get('elements') or []
                    new_elems = []
                    if isinstance(elems, list) and elems:
                        for e in elems[:MAX_CONTEXT_ELEMS]:
                            if isinstance(e, dict):
                                # only allow mrkdwn or text elements
                                if e.get('type') == 'mrkdwn' or e.get('type') == 'text':
                                    new_elems.append({'type': 'mrkdwn', 'text': _ensure_str(e.get('text', ''), 500)})
                            else:
                                new_elems.append({'type': 'mrkdwn', 'text': _ensure_str(e, 500)})
                    if new_elems:
                        nb['elements'] = new_elems

                # Divider and other allowed block types: pass through minimal
                elif bt == 'divider':
                    # divider has no additional keys
                    pass
                else:
                    # Unknown block type: skip
                    continue

                sanitized_blocks.append(nb)
                # enforce max blocks
                if len(sanitized_blocks) >= MAX_BLOCKS:
                    omitted += max(0, len(blocks) - len(sanitized_blocks))
                    break

            # If we omitted blocks, append a short summary block
            if omitted:
                sanitized_blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': _ensure_str(f'...omitted {omitted} additional blocks for brevity', 200)}})

            payload['blocks'] = sanitized_blocks

            logger.debug('Slack payload sanitized: blocks=%d; Connector payload sample type=%s', len(sanitized_blocks), type(raw_notifications))

            import requests
            resp = requests.post(url, json=payload)
            if resp.status_code >= 400:
                logger.error("Slack webhook error %s: %s", resp.status_code, resp.text)
        except Exception:
            logger.exception("Failed to send Slack notification")
