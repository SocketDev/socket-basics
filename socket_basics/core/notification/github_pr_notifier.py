import json
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseNotifier

logger = logging.getLogger(__name__)


class GithubPRNotifier(BaseNotifier):
    """Post per-group comments to a GitHub PR. Works in GH Actions (GITHUB_* envs)
    or locally/CI by using git to discover repo and branch. Uses GITHUB_TOKEN
    (or INPUT_GITHUB_TOKEN) to authenticate. Attempts to find an open PR for
    the branch; if found, it will fetch existing comments and update them per
    group. If a previous comment exists, it will merge items using checkboxes
    and mark resolved items as checked.
    """

    name = "github_pr"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        self.token = (
            self.config.get('token')
            or os.getenv('GITHUB_TOKEN')
            or os.getenv('INPUT_GITHUB_TOKEN')
        )

    # Helpers to discover repo, branch, and PR number
    def _discover_repo(self, facts: Dict[str, Any]) -> Optional[str]:
        # priority: GitHub event/env, git remote, facts (facts often come from --workspace)
        # Prefer explicit GitHub environment or event payload first
        repo = os.getenv('GITHUB_REPOSITORY')
        try:
            # Prefer structured event file path
            event_path = os.getenv('GITHUB_EVENT_PATH')
            ev = None
            if event_path and os.path.exists(event_path):
                with open(event_path, 'r') as fh:
                    ev = json.load(fh)
            else:
                # Also allow inline JSON in GITHUB_EVENT
                ev_raw = os.getenv('GITHUB_EVENT')
                if ev_raw:
                    try:
                        ev = json.loads(ev_raw)
                    except Exception:
                        ev = None

            if ev:
                pr = ev.get('pull_request') or ev.get('pullRequest')
                if pr:
                    head = pr.get('head') or {}
                    repo_info = head.get('repo') or pr.get('base', {}).get('repo')
                    if repo_info and repo_info.get('full_name'):
                        repo = repo_info.get('full_name')
        except Exception:
            pass

        # If not found via env/event, try local git remote
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
            except Exception:
                pass

        # Finally, fall back to facts (often populated from --workspace)
        if not repo:
            repo = facts.get('repository') or None

        return repo

    def _discover_branch(self, facts: Dict[str, Any]) -> Optional[str]:
        # Prefer GitHub env or event payload first, then local git, then facts
        branch = os.getenv('GITHUB_REF') or os.getenv('GITHUB_HEAD_REF')
        try:
            event_path = os.getenv('GITHUB_EVENT_PATH')
            ev = None
            if event_path and os.path.exists(event_path):
                with open(event_path, 'r') as fh:
                    ev = json.load(fh)
            else:
                ev_raw = os.getenv('GITHUB_EVENT')
                if ev_raw:
                    try:
                        ev = json.loads(ev_raw)
                    except Exception:
                        ev = None

            if ev:
                pr = ev.get('pull_request') or ev.get('pullRequest')
                if pr:
                    head = pr.get('head') or {}
                    branch = head.get('ref') or ev.get('ref') or branch
        except Exception:
            pass

        # If not available from env/event, try local git
        if not branch:
            try:
                branch = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], text=True).strip()
            except Exception:
                branch = None

        # Finally, fall back to facts (often populated from --workspace)
        if not branch:
            branch = facts.get('branch') or None

        if branch and branch.startswith('refs/heads/'):
            branch = branch.split('refs/heads/')[-1]

        return branch

    def _api_headers(self) -> Dict[str, str]:
        headers = {'Accept': 'application/vnd.github+json'}
        if self.token:
            headers['Authorization'] = f"token {self.token}"
        return headers

    def _api_base(self) -> str:
        # Allow overriding API base for GH Enterprise or custom endpoints.
        # Priority: config, INPUT_GITHUB_API_URL, GITHUB_API_URL, GITHUB_SERVER_URL, default api.github.com
        api = self.config.get('api_base') or os.getenv('INPUT_GITHUB_API_URL') or os.getenv('GITHUB_API_URL') or os.getenv('GITHUB_SERVER_URL')
        if api:
            # normalize to host only or full url
            api = api.rstrip('/')
            if not api.startswith('http'):
                api = f"https://{api}"
        else:
            api = 'https://api.github.com'
        return api

    def _split_owner_repo(self, owner_repo: str) -> Tuple[Optional[str], Optional[str]]:
        """Safely split an owner/repo string into (owner, repo).

        Returns (None, None) if the format is invalid.
        """
        try:
            owner, repo = owner_repo.split('/')
            return owner, repo
        except Exception:
            return None, None

    def _render_location_and_snippet(self, repo_rel: str, ref: str, start: str, end: str, snippet: str) -> List[str]:
        """Return lines for the location and optional snippet in the requested format.

        Output example:
        "    * location: [path/to/file](relative_link) - `start`-`end`"

            ```
            CODE
            ```
        """
        out: List[str] = []
        start_s = str(start) if start is not None else ''
        end_s = str(end) if end is not None else ''
        if start_s and end_s:
            display_range = f"`{start_s}`-`{end_s}`"
        elif start_s:
            display_range = f"`{start_s}`-`{start_s}`"
        else:
            display_range = ''

        anchor = ''
        if start_s and end_s:
            anchor = f"L{start_s}-L{end_s}"
        elif start_s:
            anchor = f"L{start_s}"

        if anchor:
            rel = f"/blob/{ref}/{repo_rel}#{anchor}"
            if display_range:
                out.append(f"    * location: [{repo_rel}]({rel}) - {display_range}")
            else:
                out.append(f"    * location: [{repo_rel}]({rel})")
        else:
            if display_range:
                out.append(f"    * location: [{repo_rel}] - {display_range}")
            else:
                out.append(f"    * location: [{repo_rel}]")

        if snippet:
            sn = snippet if len(snippet) <= 800 else snippet[:800] + '...'
            indented_block = ['', '        ```'] + [f'        {l}' for l in sn.splitlines()] + ['        ```']
            out.extend(indented_block)

        return out

    def _parse_checklist(self, body: str) -> List[Dict[str, Any]]:
        """Parse a markdown checklist in the comment body.

        Returns a list of dicts: {'text': <str>, 'checked': <bool>}
        Recognizes lines like:
          - [ ] some text
          - [x] some text
        Also tolerates leading spaces and other list markers.
        """
        items: List[Dict[str, Any]] = []
        if not body:
            return items

        for line in body.splitlines():
            line = line.strip()
            m = re.match(r"^[-*+]\s*\[( |x|X)\]\s*(.*)$", line)
            if m:
                checked = (m.group(1).lower() == 'x')
                text = m.group(2).strip()
                items.append({'text': text, 'checked': checked})
        return items

    def _render_checklist(self, items: List[Dict[str, Any]]) -> str:
        """Render checklist items (list of {'text':..., 'checked': bool}) into markdown."""
        out_lines: List[str] = []
        for it in items:
            checked = it.get('checked', False)
            box = 'x' if checked else ' '
            text = it.get('text', '')
            out_lines.append(f"- [{box}] {text}")
        return '\n'.join(out_lines)

    def _find_pr_for_branch(self, owner_repo: str, branch: str) -> Optional[int]:
        # Query PRs matching head branch via GitHub API
        try:
            import requests
        except Exception:
            logger.error('requests library required for GithubPRNotifier')
            return None
        owner, repo = self._split_owner_repo(owner_repo)
        if not owner or not repo:
            return None
        base = self._api_base()
        url = f"{base}/repos/{owner}/{repo}/pulls?state=open&head={owner}:{branch}"
        resp = requests.get(url, headers=self._api_headers())
        if resp.status_code != 200:
            logger.debug('Failed to list PRs: %s %s', resp.status_code, resp.text)
            return None
        prs = resp.json() or []
        if prs:
            return prs[0].get('number')
        return None

    def _list_comments(self, owner_repo: str, pr_number: int) -> List[Dict[str, Any]]:
        try:
            import requests
        except Exception:
            logger.error('requests library required for GithubPRNotifier')
            return []
        owner, repo = self._split_owner_repo(owner_repo)
        if not owner or not repo:
            logger.error('Invalid owner/repo format for pr comment: %s', owner_repo)
            return []
        base = self._api_base()
        url = f"{base}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        resp = requests.get(url, headers=self._api_headers())
        if resp.status_code != 200:
            logger.debug('Failed to list comments: %s %s', resp.status_code, resp.text)
            return []
        return resp.json() or []

    def _post_comment(self, owner_repo: str, pr_number: int, body: str) -> Optional[Dict[str, Any]]:
        try:
            import requests
        except Exception:
            logger.error('requests library required for GithubPRNotifier')
            return None
        owner, repo = self._split_owner_repo(owner_repo)
        if not owner or not repo:
            logger.error('Invalid owner/repo format for posting comment: %s', owner_repo)
            return None
        base = self._api_base()
        url = f"{base}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        resp = requests.post(url, headers=self._api_headers(), json={'body': body})
        if resp.status_code not in (200, 201):
            logger.error('Failed to post comment: %s %s', resp.status_code, resp.text)
            return None
        return resp.json()

    def _update_comment(self, owner_repo: str, comment_id: int, body: str) -> Optional[Dict[str, Any]]:
        """Update an existing PR/issue comment by id.

        Uses the issues comments endpoint: PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}
        """
        try:
            import requests
        except Exception:
            logger.error('requests library required for GithubPRNotifier')
            return None
        owner, repo = self._split_owner_repo(owner_repo)
        if not owner or not repo:
            logger.error('Invalid owner/repo format for updating comment: %s', owner_repo)
            return None
        base = self._api_base()
        url = f"{base}/repos/{owner}/{repo}/issues/comments/{comment_id}"
        resp = requests.patch(url, headers=self._api_headers(), json={'body': body})
        if resp.status_code != 200:
            logger.error('Failed to update comment: %s %s', resp.status_code, resp.text)
            return None
        return resp.json()
    def notify(self, facts: Dict[str, Any]) -> None:
        # Require canonical notifications provided by NotificationManager.
        notifications = facts.get('notifications')
        if not notifications:
            logger.info('GithubPRNotifier: no notifications present in facts; skipping')
            return

        # Normalize into mapping title -> rows
        normalized: Dict[str, List[Any]] = {}
        if isinstance(notifications, list):
            for item in notifications:
                if not isinstance(item, dict):
                    continue
                title = item.get('title') or 'results'
                rows = item.get('rows') or []
                normalized[title] = rows
        elif isinstance(notifications, dict):
            for title, payload in notifications.items():
                if isinstance(payload, dict):
                    normalized[title] = payload.get('rows') or []
                elif isinstance(payload, list):
                    normalized[title] = payload

        owner_repo = self._discover_repo(facts)
        branch = self._discover_branch(facts)

        if not owner_repo or not branch:
            logger.info('Could not determine repository or branch for PR notifier')
            return

        pr_number = None
        pr_env = os.getenv('GITHUB_PR_NUMBER') or os.getenv('INPUT_PR_NUMBER')
        if pr_env and pr_env.isdigit():
            pr_number = int(pr_env)
        else:
            pr_number = self._find_pr_for_branch(owner_repo, branch)

        if not pr_number:
            logger.info('No pull request found for branch %s in %s', branch, owner_repo)
            return

        existing_comments = self._list_comments(owner_repo, pr_number)

        bot_comments = []
        uid = f"socket-security:{owner_repo}:{branch}"
        marker = f"<!-- {uid} -->"
        for c in existing_comments:
            if not c:
                continue
            body = c.get('body', '') or ''
            if marker in body:
                bot_comments.append(c)

        for group_label, rows in normalized.items():
            items: List[Dict[str, Any]] = []
            for r in rows:
                try:
                    # Expected canonical OpenGrep row shape: [Rule, Severity, File, Path, Lines, Code]
                    if group_label.lower().startswith('sast') and len(r) >= 3:
                        rule = str(r[0]) if len(r) > 0 else ''
                        severity = str(r[1]) if len(r) > 1 else ''
                        file_name = str(r[2]) if len(r) > 2 else ''
                        file_path = str(r[3]) if len(r) > 3 else (str(r[2]) if len(r) > 2 else '')
                        loc = str(r[4]) if len(r) > 4 else ''
                        snippet = str(r[5]) if len(r) > 5 else str(r[4]) if len(r) > 4 else ''
                        # Store both display file name and the full path (used for links)
                        items.append({'rule': rule, 'severity': severity, 'file': file_name, 'path': file_path, 'loc': loc, 'snippet': snippet, 'checked': False})
                    else:
                        # Preserve raw table or preformatted strings for non-SAST (and non-secrets) groups.
                        # If the row is a single string (likely a markdown table or block), keep it in 'raw'
                        if isinstance(r, str):
                            items.append({'text': str(r), 'raw': str(r), 'checked': False})
                        elif isinstance(r, list) and len(r) == 1 and isinstance(r[0], str):
                            items.append({'text': r[0], 'raw': r[0], 'checked': False})
                        else:
                            desc = ' | '.join([str(x) for x in r if x is not None and x != ''])
                            items.append({'text': desc, 'checked': False})
                except Exception:
                    desc = ' | '.join([str(x) for x in r if x is not None and x != ''])
                    items.append({'text': desc, 'checked': False})

            prev_comment = None
            prev_items: List[Dict[str, Any]] = []
            for c in bot_comments:
                body = c.get('body', '') or ''
                if f"### {group_label}" in body:
                    prev_comment = c
                    prev_items = self._parse_checklist(body)
                    break

            prev_texts = {p['text']: p.get('checked', False) for p in prev_items}

            merged: List[Dict[str, Any]] = []
            if group_label.lower().startswith('sast'):
                grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
                for it in items:
                    rule = it.get('rule', '')
                    # Use the full path (path) for link generation and grouping
                    file_path = it.get('path', '')
                    loc = it.get('loc', '')
                    snippet = it.get('snippet', '')

                    checked = False
                    cand1 = rule
                    cand2 = f"{rule} | {file_path} | {loc}"
                    if cand1 in prev_texts:
                        checked = prev_texts.get(cand1, False)
                    elif cand2 in prev_texts:
                        checked = prev_texts.get(cand2, False)

                    grouped.setdefault(rule, {}).setdefault(file_path, []).append({'loc': loc, 'snippet': snippet, 'checked': checked})

                for rule, files in grouped.items():
                    merged.append({'rule': rule, 'files': files})
            else:
                for it in items:
                    text = it.get('text', '')
                    checked = prev_texts.get(text, False)
                    merged.append({'text': text, 'checked': checked})

            total = 0
            if group_label.lower().startswith('sast'):
                for m in merged:
                    files_map = m.get('files') or {}
                    if isinstance(files_map, dict) and files_map:
                        for file_list in files_map.values():
                            total += len(file_list)
                    else:
                        for mf in (m.get('manifestFiles') or []):
                            total += 1
            else:
                total = len(merged)

            if total == 0:
                if prev_comment and prev_items:
                    updated_items = []
                    for it in prev_items:
                        updated_items.append({'checked': True, 'text': it.get('text', '')})
                    new_body = marker + '\n\n' + f"### {group_label}\n\nSocket Security findings for *{owner_repo}* on branch `{branch}` — *0 alert(s)*." + '\n\n' + self._render_checklist(updated_items) + '\n\n_This comment is managed by Socket Security notifier._'
                    logger.info('Marking existing PR comment as resolved for group %s', group_label)
                    self._update_comment(owner_repo, prev_comment.get('id'), new_body)
                else:
                    logger.info('No alerts and no previous comment for group %s — nothing to post', group_label)
                continue

            header = f"### {group_label}\n\nSocket Security findings for *{owner_repo}* on branch `{branch}` — *{total} alert(s)*."
            lines: List[str] = [marker, '', header, '']

            if group_label.lower().startswith('sast'):
                for m in merged:
                    rule = m.get('rule', '')
                    files = m.get('files', {}) or {}

                    def render_file_occurrences(file_path: str, occs: List[Dict[str, Any]]):
                        file_key = f"{rule} | {file_path}"
                        any_occ_checked = any(occ.get('checked', False) for occ in occs)
                        checked = prev_texts.get(file_key, False) or any_occ_checked
                        box = 'x' if checked else ' '
                        lines.append(f"- [{box}] {rule}")

                        repo_rel = file_path
                        try:
                            cwd = facts.get('cwd')
                            if not cwd:
                                git_root = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
                                cwd = git_root
                        except Exception:
                            cwd = None
                        try:
                            if repo_rel and cwd and repo_rel.startswith(cwd):
                                repo_rel = repo_rel[len(cwd):].lstrip('/').lstrip('./')
                        except Exception:
                            pass

                        basename = os.path.basename(repo_rel) or repo_rel
                        lines.append(f"    File: `{basename}`")

                        for occ in occs:
                            loc = occ.get('loc', '')
                            snippet = occ.get('snippet', '')
                            start = ''
                            end = ''
                            if loc and '-' in str(loc):
                                parts = str(loc).split('-', 1)
                                start = parts[0]
                                end = parts[1]
                            else:
                                start = str(loc)

                            ref = os.getenv('GITHUB_SHA') or branch
                            lines.extend(self._render_location_and_snippet(repo_rel, ref, start, end, snippet))

                    if isinstance(files, dict) and files:
                        for file_path, occs in files.items():
                            render_file_occurrences(file_path, occs)
                    else:
                        for mf in (m.get('manifestFiles') or []):
                            fpath = mf.get('file', '')
                            occs = [{'loc': mf.get('start') or '', 'snippet': mf.get('snippet') or ''}]
                            render_file_occurrences(fpath, occs)
            else:
                for it in merged:
                    # If the item contains a 'raw' key, emit it verbatim to preserve
                    # preformatted tables or markdown blocks (e.g., Trivy table output).
                    raw = it.get('raw')
                    if raw:
                        # Ensure there's a blank line before and after a block for readability
                        if lines and lines[-1] != '':
                            lines.append('')
                        for l in str(raw).splitlines():
                            lines.append(l)
                        if lines[-1] != '':
                            lines.append('')
                        continue

                    checked = it.get('checked', False)
                    box = 'x' if checked else ' '
                    text = it.get('text', '')
                    lines.append(f"- [{box}] {text}")

            lines.append('_This comment is provided by Socket Security._')
            body = '\n'.join(lines)

            if prev_comment:
                logger.info('Updating existing PR comment for group %s', group_label)
                self._update_comment(owner_repo, prev_comment.get('id'), body)
            else:
                logger.info('Posting new PR comment for group %s', group_label)
                self._post_comment(owner_repo, pr_number, body)
