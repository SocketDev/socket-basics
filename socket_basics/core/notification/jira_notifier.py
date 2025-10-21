from typing import Any, Dict, Optional
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import (
    get_jira_url, get_jira_project, get_jira_email, 
    get_jira_api_token, get_github_repository
)

logger = logging.getLogger(__name__)


class JiraNotifier(BaseNotifier):
    """JIRA notifier: creates JIRA issues for security findings.
    
    Creates a main issue with summary table and adds each scanner result as a comment.
    """

    name = "jira"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # JIRA configuration from params, env variables, or app config
        self.server = (
            self.config.get('server') or
            get_jira_url()
        )
        self.project = (
            self.config.get('project') or
            get_jira_project()
        )
        self.email = (
            self.config.get('email') or
            get_jira_email()
        )
        self.api_token = (
            self.config.get('api_token') or
            get_jira_api_token()
        )
        
        # Get repository from config or environment
        self.repository = (
            self.config.get('repository') or
            get_github_repository() or
            'Unknown'
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('JiraNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('JiraNotifier: no notifications present; skipping')
            return

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                valid_notifications.append(item)
            else:
                logger.warning('JiraNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Get repository info from facts (passed from main config)
        repo = facts.get('repository', self.repository)
        branch = facts.get('branch', 'Unknown') 
        commit_hash = facts.get('commit_hash', 'Unknown')
        full_scan_url = facts.get('full_scan_html_url')
        
        logger.info('JiraNotifier: repo=%s, branch=%s, commit_hash=%s', repo, branch, commit_hash)
        if full_scan_url:
            logger.info('JiraNotifier: full_scan_url=%s', full_scan_url)
        
        # Create main issue title in format: "Socket Security Results - repo - branch - commit_hash"
        title_parts = ["Socket Security Results"]
        if repo and repo != 'Unknown':
            title_parts.append(repo)
        if branch and branch != 'Unknown':
            title_parts.append(branch)
        if commit_hash and commit_hash != 'Unknown':
            title_parts.append(commit_hash[:8])  # Short hash for readability
        
        main_title = " - ".join(title_parts)
        logger.info('JiraNotifier: main title: %s', main_title)
        
        # Create summary table showing scanner findings
        summary_content = self._create_summary_table(valid_notifications)
        
        # Try to find existing issue with same title
        existing_issue = self._find_existing_issue(main_title)
        
        if existing_issue:
            issue_key = existing_issue['key']
            logger.info('JiraNotifier: found existing issue %s, will update', issue_key)
            # Update description with new summary
            self._update_issue_description(issue_key, summary_content)
        else:
            # Create main issue with summary
            issue_key = self._create_main_issue(main_title, summary_content)
        
        if issue_key:
            # Add each scanner result as a separate comment
            for notification in valid_notifications:
                self._add_comment_to_issue(issue_key, notification['title'], notification['content'], full_scan_url)



    def _create_summary_table(self, notifications: list) -> str:
        """Create a summary table showing scanner findings count."""
        # Create summary table with scanner names and count of findings
        summary_lines = ['|| Scanner || Findings ||']
        
        for notification in notifications:
            title = notification.get('title', 'Unknown Scanner')
            content = notification.get('content', {})
            
            # Count findings from ADF table rows
            row_count = self._count_adf_table_rows(content)
                
            summary_lines.append(f'| {title} | {row_count} |')
        
        return '\n'.join(summary_lines)

    def _count_adf_table_rows(self, content: Dict[str, Any]) -> int:
        """Count data rows in ADF table format."""
        if not isinstance(content, dict) or content.get('type') != 'doc':
            return 0
        
        # Look for table in ADF content
        for item in content.get('content', []):
            if item.get('type') == 'table':
                table_rows = item.get('content', [])
                # Count data rows (exclude header row)
                data_rows = [row for row in table_rows if row.get('type') == 'tableRow'][1:]  # Skip header
                return len(data_rows)
            elif item.get('type') == 'paragraph':
                # Check if it's a "No ... found" message
                text_content = self._extract_text_from_adf_paragraph(item)
                if 'No ' in text_content and ' found' in text_content:
                    return 0
        
        # If no table found but content exists, assume 1 finding
        return 1 if content.get('content') else 0

    def _extract_text_from_adf_paragraph(self, paragraph: Dict[str, Any]) -> str:
        """Extract text content from ADF paragraph."""
        text_parts = []
        for content_item in paragraph.get('content', []):
            if content_item.get('type') == 'text':
                text_parts.append(content_item.get('text', ''))
        return ''.join(text_parts)

    def _create_main_issue(self, title: str, summary_content: str) -> Optional[str]:
        """Create main Jira issue with summary table and return issue key."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth

            # Create ADF format description with summary table
            summary_table_adf = self._convert_jira_table_to_adf(summary_content.split('\n'))
            
            description_content = [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Socket Security scan results summary:"}
                    ]
                }
            ]
            
            # Add the summary table
            description_content.extend(summary_table_adf)
            
            # Add footer paragraph
            description_content.append({
                "type": "paragraph", 
                "content": [
                    {"type": "text", "text": "Detailed findings are provided in the comments below."}
                ]
            })
            
            description_adf = {
                "type": "doc",
                "version": 1,
                "content": description_content
            }

            payload = {
                "fields": {
                    "project": {"key": self.project},
                    "summary": title,
                    "description": description_adf,
                    "issuetype": {"name": "Task"}
                }
            }

            auth = HTTPBasicAuth(str(self.email), str(self.api_token))
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            url = f"{self.server}/rest/api/3/issue"
            resp = requests.post(url, auth=auth, headers=headers, json=payload, timeout=10)

            if resp.status_code == 201:
                issue = resp.json()
                issue_key = issue.get('key')
                logger.info('JiraNotifier: created main issue %s', issue_key)
                return issue_key
            else:
                logger.warning('JiraNotifier: failed to create main issue: %s - %s', resp.status_code, resp.text)
                return None

        except Exception as e:
            logger.error('JiraNotifier: exception creating main issue: %s', e)
            return None

    def _add_comment_to_issue(self, issue_key: str, title: str, content: Dict[str, Any], full_scan_url: str | None = None) -> None:
        """Add a comment with scanner results to the main Jira issue."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth

            # Content should be in ADF format
            comment_adf = content.copy()
            
            # Add title as heading if provided
            if title:
                title_heading = {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": title}]
                }
                # Insert title at the beginning of content
                comment_adf["content"] = [title_heading] + comment_adf.get("content", [])
            
            # Add full scan URL at the end if available
            if full_scan_url:
                # Add a divider
                divider = {"type": "rule"}
                
                # Add paragraph with link to full results
                scan_url_paragraph = {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "🔗 "},
                        {
                            "type": "text",
                            "text": "View Full Socket Scan",
                            "marks": [
                                {
                                    "type": "link",
                                    "attrs": {"href": full_scan_url}
                                }
                            ]
                        }
                    ]
                }
                
                # Append to content
                comment_adf["content"].append(divider)
                comment_adf["content"].append(scan_url_paragraph)

            payload = {
                "body": comment_adf
            }

            auth = HTTPBasicAuth(str(self.email), str(self.api_token))
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            url = f"{self.server}/rest/api/3/issue/{issue_key}/comment"
            resp = requests.post(url, auth=auth, headers=headers, json=payload, timeout=10)

            if resp.status_code == 201:
                logger.info('JiraNotifier: added comment to issue %s for %s', issue_key, title)
            else:
                # Include source (title) and response body in warning for debugging
                try:
                    error_detail = resp.json()
                except Exception:
                    error_detail = resp.text[:200]  # First 200 chars of response
                logger.warning('JiraNotifier (%s): failed to add comment to issue %s: %s - %s', 
                             title, issue_key, resp.status_code, error_detail)

        except Exception as e:
            logger.error('JiraNotifier (%s): exception adding comment to issue: %s', title, e)

    def _convert_jira_table_to_adf(self, table_lines: list) -> list:
        """Convert Jira table markup to ADF table format."""
        if not table_lines:
            return []
        
        table_rows = []
        
        for line in table_lines:
            line = line.strip()
            if line.startswith('||') and line.endswith('||'):
                # Header row
                headers = [cell.strip() for cell in line[2:-2].split('||')]
                header_cells = []
                for header in headers:
                    header_cells.append({
                        "type": "tableHeader",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "text": header}]
                            }
                        ]
                    })
                table_rows.append({
                    "type": "tableRow",
                    "content": header_cells
                })
            elif line.startswith('|') and line.endswith('|'):
                # Data row
                cells = [cell.strip() for cell in line[1:-1].split('|')]
                data_cells = []
                for i, cell in enumerate(cells):
                    # Check if this cell contains code (look for common code patterns)
                    cell_content = []
                    if self._is_code_content(cell):
                        # Format as code block
                        cell_content = [
                            {
                                "type": "codeBlock",
                                "content": [{"type": "text", "text": cell}]
                            }
                        ]
                    else:
                        # Regular text
                        cell_content = [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "text": cell}]
                            }
                        ]
                    
                    data_cells.append({
                        "type": "tableCell",
                        "content": cell_content
                    })
                table_rows.append({
                    "type": "tableRow",
                    "content": data_cells
                })
        
        if table_rows:
            return [{
                "type": "table",
                "content": table_rows
            }]
        
        return []

    def _is_code_content(self, text: str) -> bool:
        """Determine if text content should be formatted as code."""
        # Check for common code patterns
        code_indicators = [
            '{', '}', '(', ')', ';', '=', 
            'function', 'var ', 'const ', 'let ',
            'import ', 'require(', 'module.exports',
            'if (', 'for (', 'while (', 'try {',
            '.', '->', '=>', '&&', '||',
            'console.log', 'Math.', 'parseInt',
            'eval(', 'userId', 'user.', 'req.',
            'allocations', 'contributions', 'users'
        ]
        
        # If text is longer than 50 chars and contains code indicators, it's likely code
        if len(text) > 50:
            code_indicator_count = sum(1 for indicator in code_indicators if indicator in text)
            if code_indicator_count >= 2:
                return True
        
        # Check for specific patterns that indicate code
        if any(pattern in text for pattern in ['{}', '()', '=>', '&&', '||', 'console.log']):
            return True
            
        return False

    def _find_existing_issue(self, title: str) -> Optional[Dict[str, Any]]:
        """Find existing Jira issue with the same title."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            # Search for issues with exact title match using the new API endpoint
            auth = HTTPBasicAuth(str(self.email), str(self.api_token))
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # Escape quotes in title for JQL
            escaped_title = title.replace('"', '\\"')
            jql = f'project = "{self.project}" AND summary ~ "{escaped_title}"'
            
            # Use the new search/jql endpoint (POST instead of GET)
            url = f"{self.server}/rest/api/3/search/jql"
            payload = {
                "jql": jql,
                "maxResults": 10,
                "fields": ["key", "summary"]
            }
            
            logger.debug('JiraNotifier: searching with JQL: %s', jql)
            
            resp = requests.post(url, auth=auth, headers=headers, json=payload, timeout=10)
            
            if resp.status_code == 200:
                search_results = resp.json()
                issues = search_results.get('issues', [])
                
                logger.debug('JiraNotifier: search returned %d issues', len(issues))
                
                # Look for exact title match
                for issue in issues:
                    issue_summary = issue.get('fields', {}).get('summary', '')
                    if issue_summary == title:
                        logger.info('JiraNotifier: found existing issue with matching title: %s', issue.get('key'))
                        return issue
                        
                return None
            elif resp.status_code == 403:
                logger.warning('JiraNotifier: search permission denied (403). Creating new issue instead of searching for existing ones.')
                return None
            elif resp.status_code == 400:
                logger.warning('JiraNotifier: invalid JQL query (400): %s. Creating new issue.', jql)
                return None
            else:
                logger.warning('JiraNotifier: failed to search for existing issues: %s - %s', resp.status_code, resp.text)
                return None
                
        except Exception as e:
            logger.error('JiraNotifier: exception searching for existing issue: %s', e)
            return None

    def _update_issue_description(self, issue_key: str, summary_content: str) -> None:
        """Update the description of an existing issue."""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            # Create ADF format description with summary table
            summary_table_adf = self._convert_jira_table_to_adf(summary_content.split('\n'))
            
            description_content = [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Socket Security scan results summary (updated):"}
                    ]
                }
            ]
            
            # Add the summary table
            description_content.extend(summary_table_adf)
            
            # Add footer paragraph
            description_content.append({
                "type": "paragraph", 
                "content": [
                    {"type": "text", "text": "Detailed findings are provided in the comments below."}
                ]
            })
            
            description_adf = {
                "type": "doc",
                "version": 1,
                "content": description_content
            }
            
            payload = {
                "fields": {
                    "description": description_adf
                }
            }
            
            auth = HTTPBasicAuth(str(self.email), str(self.api_token))
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            url = f"{self.server}/rest/api/3/issue/{issue_key}"
            resp = requests.put(url, auth=auth, headers=headers, json=payload, timeout=10)
            
            if resp.status_code == 204:
                logger.info('JiraNotifier: updated issue %s description', issue_key)
            else:
                logger.warning('JiraNotifier: failed to update issue %s: %s', issue_key, resp.status_code)
                
        except Exception as e:
            logger.error('JiraNotifier: exception updating issue description: %s', e)