from typing import Any, Dict, List, Optional
import os
from pathlib import Path
import logging
import json

from socket_basics.core.notification.base import BaseNotifier

logger = logging.getLogger(__name__)


def _adf_text_node(text: str) -> Dict[str, Any]:
    return {"type": "text", "text": text}


def _adf_paragraph(text: str) -> Dict[str, Any]:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _adf_table(headers: List[str], rows: List[List[str]]) -> Dict[str, Any]:
    """Build a Jira ADF table node from headers and rows.

    headers: list of header strings
    rows: list of row lists (strings)
    Returns a node of type 'table'.
    """
    def cell(text: str) -> Dict[str, Any]:
        return {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}

    # header row
    header_cells = [cell(h) for h in headers]
    header_row = {"type": "tableRow", "content": header_cells}

    body_rows = []
    for r in rows:
        # ensure row has same number of columns
        cells = [cell(str(r[i]) if i < len(r) else '') for i in range(len(headers))]
        body_rows.append({"type": "tableRow", "content": cells})

    table = {"type": "table", "content": [header_row] + body_rows}
    return table


class JiraNotifier(BaseNotifier):
    """Notifier that posts results to Jira using ADF tables for structured data."""

    name = "jira"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        self.server = self.config.get('server') or os.getenv('INPUT_JIRA_URL')
        self.project = self.config.get('project') or os.getenv('INPUT_JIRA_PROJECT')
        self.auth = self.config.get('auth') or {
            'email': os.getenv('INPUT_JIRA_EMAIL'),
            'api_token': os.getenv('INPUT_JIRA_API_TOKEN')
        }

    def _requests(self):
        try:
            import requests

            return requests
        except Exception:
            logger.error("requests library required for JiraNotifier")
            return None

    def _find_existing_issue(self, summary: str, auth: Optional[Any], headers: Dict[str, str], base: str) -> Optional[str]:
        requests = self._requests()
        if requests is None:
            return None

        # Build JQL to search for issues with the given summary
        jql_summary = summary.replace('"', '\\"')
        jql = f'summary ~ "{jql_summary}"'

        # Use POST /rest/api/3/search/jql per Atlassian migration guidance
        url = f"{base}/rest/api/3/search/jql"

        # Build payload exactly as in Atlassian docs example
        body = {
            "expand": "",
            "fields": ["key", "summary", "status"],
            "fieldsByKeys": True,
            "jql": jql,
            "maxResults": 1,
            "nextPageToken": "",
            "properties": [],
            "reconcileIssues": []
        }

        # Debug: log the exact payload and headers (avoid printing secrets)
        try:
            logger.debug("Jira search request: url=%s headers=%s auth=%s body=%s", url, {k: headers.get(k) for k in headers}, (type(auth).__name__ if auth is not None else None), json.dumps(body))
        except Exception:
            logger.debug("Jira search request prepared (failed to serialize body for logging)")

        resp = requests.post(url, auth=auth, headers=headers, data=json.dumps(body))
        if resp.status_code >= 400:
            # Log request/response details to help diagnose invalid payload errors
            try:
                req = getattr(resp, 'request', None)
                req_headers = dict(req.headers) if req is not None and getattr(req, 'headers', None) else {}
                # mask Authorization header if present
                if 'Authorization' in req_headers:
                    req_headers['Authorization'] = 'REDACTED'
                req_body = req.body if req is not None else None
                logger.debug("Jira search returned %s: %s", resp.status_code, resp.text)
                logger.debug("Jira request sent: method=%s url=%s headers=%s body=%s", getattr(req, 'method', None), getattr(req, 'url', None), req_headers, (req_body[:1000] if isinstance(req_body, (bytes, str)) else str(type(req_body))))
            except Exception:
                logger.debug("Jira search returned %s and failed to log request details", resp.status_code)
            return None

        data = resp.json() or {}
        issues = data.get('issues') or []
        if not issues:
            return None
        return issues[0].get('key')

    def _get_issue_status(self, issue_key: str, auth: Optional[Any], headers: Dict[str, str], base: str) -> Optional[tuple[str, Any]]:
        requests = self._requests()
        if requests is None:
            return None
        url = f"{base}/rest/api/3/issue/{issue_key}"
        resp = requests.get(url, auth=auth, headers=headers, params={"fields": "status,description"})
        if resp.status_code >= 400:
            logger.debug('Failed to fetch issue %s: %s', issue_key, resp.text)
            return None
        data = resp.json() or {}
        fields = data.get('fields') or {}
        status = (fields.get('status') or {}).get('name')
        description = fields.get('description')
        return status, description

    def _get_issue_comments(self, issue_key: str, auth: Optional[Any], headers: Dict[str, str], base: str) -> List[Dict[str, Any]]:
        requests = self._requests()
        if requests is None:
            return []
        url = f"{base}/rest/api/3/issue/{issue_key}/comment"
        resp = requests.get(url, auth=auth, headers=headers)
        if resp.status_code >= 400:
            logger.debug('Failed to fetch comments for %s: %s', issue_key, resp.text)
            return []
        data = resp.json() or {}
        return data.get('comments') or []

    def _adf_extract_table_rows(self, adf: Dict[str, Any]) -> List[List[str]]:
        """Try to extract simple string rows from an ADF doc produced by this notifier.

        This is heuristic: look for nodes of type 'table' and extract text from cells.
        """
        rows: List[List[str]] = []
        if not adf or not isinstance(adf, dict):
            return rows
        for node in adf.get('content', []) if isinstance(adf.get('content', []), list) else []:
            if node.get('type') == 'table':
                for tr in node.get('content', []):
                    if tr.get('type') != 'tableRow':
                        continue
                    cells = []
                    for tc in tr.get('content', []):
                        # find first text in cell
                        txt = ''
                        for p in tc.get('content', []):
                            if p.get('type') == 'paragraph':
                                for t in p.get('content', []):
                                    if t.get('type') == 'text':
                                        txt += t.get('text', '')
                        cells.append(txt)
                    rows.append(cells)
        # skip header row when present
        if len(rows) > 1:
            return rows[1:]
        return []

    def notify(self, facts: Dict[str, Any], should_print: bool = True) -> None:
        """Build ADF description/comment and post to Jira.

        Note: the issue summary continues to include repo/branch, but the body/comment
        will NOT contain a leading line like "Security issues detected in <repo>".
        Instead the body contains a proper ADF table representing the findings.
        """
        app_cfg = getattr(self, 'app_config', {}) or {}
        repo = (
            self.config.get('repository')
            or app_cfg.get('repository')
            or facts.get('repository')
            or os.getenv('SOCKET_REPOSITORY_NAME')
            or os.getenv('GITHUB_REPOSITORY')
            or Path(os.getcwd()).name
        )
        branch = (
            self.config.get('branch')
            or app_cfg.get('branch')
            or facts.get('branch')
            or os.getenv('GITHUB_REF_NAME')
            or 'unknown'
        )

        raw_notifications = facts.get('notifications') or {}
        # Normalize notifications into mapping: title -> {'headers': Optional[List[str]], 'rows': List[List[str]]}
        notifications: Dict[str, Dict[str, Any]] = {}
        if isinstance(raw_notifications, list):
            for t in raw_notifications:
                try:
                    title = t.get('title') or 'results'
                    headers = t.get('headers')
                    rows = t.get('rows') or []
                    existing = notifications.setdefault(title, {'headers': None, 'rows': []})
                    # Prefer headers provided by the connector if not already set
                    if headers and not existing.get('headers'):
                        existing['headers'] = headers
                    existing['rows'].extend(rows)
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
                        notifications[title] = {'headers': None, 'rows': payload}
                    else:
                        notifications[title] = {'headers': None, 'rows': []}
                except Exception:
                    notifications[title] = {'headers': None, 'rows': []}

        # Do NOT synthesize notifications from components. The ConnectorManager
        # is responsible for validating and providing canonical notification
        # tables. If none are present, log and continue with an empty doc.
        if not notifications:
            logger.warning('JiraNotifier: no canonical notifications provided; skipping creation of notification tables')

        # Build ADF content blocks: a short paragraph header (optional) and a table
        adf_content: List[Dict[str, Any]] = []

        # For each group, create a separate table with a heading paragraph
        for group_label, payload in notifications.items():
            rows = payload.get('rows') or []
            provided_headers = payload.get('headers')

            # heading paragraph for group
            adf_content.append(_adf_paragraph(f"{group_label}"))

            # Use only connector-provided headers. Manager enforces that headers
            # are present and valid; if a group lacks headers here, skip it.
            if not provided_headers or not isinstance(provided_headers, list):
                logger.warning("JiraNotifier: skipping group '%s' because headers absent or invalid; notifiers should only receive validated tables", group_label)
                continue
            # Use connector-provided headers; limit to available columns if rows present
            col_count = len(rows[0]) if rows else 0
            headers = provided_headers[:col_count] if col_count else provided_headers

            # truncate/normalize cells
            norm_rows: List[List[str]] = []
            for r in rows[:50]:
                norm = []
                for i in range(len(headers)):
                    cell = r[i] if i < len(r) else ''
                    s = str(cell) if cell is not None else ''
                    s = " ".join(s.split())
                    if len(s) > 800:
                        s = s[:800] + '...'
                    norm.append(s)
                norm_rows.append(norm)

            adf_content.append(_adf_table(headers, norm_rows))

        # Fallback: if no notifications, include a short paragraph
        if not adf_content:
            adf_content.append(_adf_paragraph("No security issues detected in scanned components."))

        # Build final ADF doc
        adf_doc = {"type": "doc", "version": 1, "content": adf_content}

        should_print = bool(self.config.get('print_comment'))

        # Validate credentials
        auth_ok = False
        if isinstance(self.auth, dict):
            auth_ok = bool(self.auth.get('email') and self.auth.get('api_token'))
        elif isinstance(self.auth, str):
            auth_ok = bool(self.auth)

        if not (self.server and self.project and auth_ok):
            missing = []
            if not self.server:
                missing.append('server')
            if not self.project:
                missing.append('project')
            if not auth_ok:
                missing.append('auth')
            logger.info("Jira notifier not fully configured; skipping remote post (missing: %s)", ','.join(missing) if missing else 'none')
            logger.debug("Jira ADF content: %s", adf_doc)
            if should_print:
                try:
                    print(adf_doc)
                except Exception:
                    logger.debug('Failed to print Jira ADF doc to stdout')
            return

        requests = self._requests()
        if requests is None:
            if should_print:
                print(adf_doc)
            return

        auth = None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if isinstance(self.auth, dict) and self.auth.get('email') and self.auth.get('api_token'):
            auth = (self.auth.get('email'), self.auth.get('api_token'))
        elif isinstance(self.auth, str) and self.auth:
            headers['Authorization'] = f"Bearer {self.auth}"

        base = self.server.rstrip('/')
        summary = self.config.get('summary') or f"Socket Security Issues detected in {repo} - {branch}"

        try:
            found_key = self._find_existing_issue(summary, auth, headers, base)
        except Exception:
            logger.exception('Error while searching for existing Jira issue')
            found_key = None

        if found_key:
            # fetch issue status and description
            try:
                status_desc = self._get_issue_status(found_key, auth, headers, base)
            except Exception:
                status_desc = None
            if status_desc:
                status, existing_description = status_desc
            else:
                status, existing_description = None, None

            # if the existing issue is resolved/done/closed, create a new one instead
            if status and status.lower() in ('done', 'closed', 'resolved', 'complete'):
                logger.info('Found existing issue %s but status is %s -> creating a new issue', found_key, status)
                found_key = None
            else:
                # gather existing rows from description and comments
                existing_rows: List[List[str]] = []
                if existing_description and isinstance(existing_description, dict):
                    existing_rows.extend(self._adf_extract_table_rows(existing_description))
                try:
                    comments = self._get_issue_comments(found_key, auth, headers, base)
                    for c in comments:
                        body = c.get('body')
                        if isinstance(body, dict):
                            existing_rows.extend(self._adf_extract_table_rows(body))
                except Exception:
                    logger.exception('Error fetching comments for %s', found_key)

                # build current rows for comparison (flatten to strings)
                current_rows: List[List[str]] = []
                for node in adf_doc.get('content', []):
                    if node.get('type') == 'table':
                        # reuse our extract helper by wrapping
                        current_rows.extend(self._adf_extract_table_rows({'content': [node]}))

                # normalize comparison by joining cells
                def join_row(r: List[str]) -> str:
                    return '|'.join([s.strip() for s in r])

                existing_set = set(join_row(r) for r in existing_rows)
                new_rows = [r for r in current_rows if join_row(r) not in existing_set]

                if not new_rows:
                    logger.info('No new alerts to post to %s; skipping comment', found_key)
                    if should_print:
                        try:
                            print({'posted': False, 'issue': found_key})
                        except Exception:
                            logger.debug('Failed to print Jira post status to stdout')
                    return

                # build a small adf doc for only new rows and post as a comment
                table_headers: List[str] = []
                # infer headers from the first table node in adf_doc
                for node in adf_doc.get('content', []):
                    if node.get('type') == 'table':
                        # infer header text
                        first_row = node.get('content', [])[0] if node.get('content') else None
                        if first_row and first_row.get('type') == 'tableRow':
                            hdrs: List[str] = []
                            for cell in first_row.get('content', []):
                                # extract text
                                t = ''
                                for p in cell.get('content', []):
                                    if p.get('type') == 'paragraph':
                                        for txt in p.get('content', []):
                                            if txt.get('type') == 'text':
                                                t += txt.get('text', '')
                                hdrs.append(t)
                            table_headers = hdrs
                        break

                comment_doc = {"type": "doc", "version": 1, "content": []}
                comment_doc['content'].append(_adf_paragraph('New alerts'))
                comment_doc['content'].append(_adf_table(table_headers or [f'Col{i+1}' for i in range(len(new_rows[0]))], new_rows))

                url = f"{base}/rest/api/3/issue/{found_key}/comment"
                payload = {"body": comment_doc}
                # use a validated auth tuple if available
                auth_to_use = auth if isinstance(auth, tuple) and len(auth) == 2 and all(isinstance(x, str) and x for x in auth) else None
                resp = requests.post(url, auth=auth_to_use, headers=headers, json=payload)
                if resp.status_code >= 400:
                    logger.error('Failed to post Jira comment %s: %s', resp.status_code, resp.text)
                else:
                    issue_url = f"{base}/browse/{found_key}"
                    logger.info('Posted Jira comment to %s (%s)', found_key, issue_url)
                if should_print:
                        try:
                            print({'posted': True, 'issue': found_key, 'new_count': len(new_rows)})
                        except Exception:
                            logger.debug('Failed to print Jira post status to stdout')
                return

        # Create a new issue
        new_issue_url = f"{base}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary,
                "description": adf_doc,
                "issuetype": {"name": self.config.get('issuetype') or 'Task'}
            }
        }

        # Ensure we have a requests module to use
        http = self._requests()
        if http is None:
            if should_print:
                try:
                    print(adf_doc)
                except Exception:
                    logger.debug('Failed to print Jira ADF doc to stdout')
            return

        # Validate auth tuple (user, token) before passing to requests
        auth_to_use = auth if isinstance(auth, tuple) and len(auth) == 2 and all(isinstance(x, str) and x for x in auth) else None

        try:
            resp = http.post(new_issue_url, auth=auth_to_use, headers=headers, json=payload)
            if resp.status_code >= 400:
                logger.error('Failed to create Jira issue %s: %s', resp.status_code, resp.text)
            else:
                try:
                    created = resp.json()
                    k = created.get('key')
                    issue_url = f"{base}/browse/{k}" if k else base
                    logger.info('Created Jira issue %s (%s)', k, issue_url)
                except Exception:
                    logger.info('Created Jira issue (response did not contain key)')
        except Exception:
            logger.exception('Failed to create Jira issue')

        if should_print:
            try:
                print(adf_doc)
            except Exception:
                logger.debug('Failed to print Jira ADF doc to stdout')
