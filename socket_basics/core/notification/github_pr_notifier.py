from typing import Any, Dict, List, Optional
import logging

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import get_github_token, get_github_repository, get_github_pr_number

logger = logging.getLogger(__name__)

# GitHub API comment character limit
GITHUB_COMMENT_MAX_LENGTH = 65536


class GithubPRNotifier(BaseNotifier):
    """GitHub PR notifier: posts security findings as PR comments.
    
    Simplified version that works with pre-formatted content from connectors.
    """

    name = "github_pr"

    def __init__(self, params: Dict[str, Any] | None = None):
        super().__init__(params or {})
        # GitHub token from params, env variable, or app config
        self.token = (
            self.config.get('token') or
            get_github_token()
        )
        self.api_base = "https://api.github.com"
        
        # Get repository from GitHub environment
        self.repository = (
            self.config.get('repository') or
            get_github_repository()
        )

    def notify(self, facts: Dict[str, Any]) -> None:
        notifications = facts.get('notifications', []) or []
        
        if not isinstance(notifications, list):
            logger.error('GithubPRNotifier: only supports new format - list of dicts with title/content')
            return
            
        if not notifications:
            logger.info('GithubPRNotifier: no notifications present; skipping')
            return

        # Get full scan URL if available and store it for use in truncation
        self.full_scan_url = facts.get('full_scan_html_url')

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                # Append full scan URL to content if available
                content = item['content']
                if self.full_scan_url:
                    content += f"\n\n---\n\n🔗 [View Full Socket Scan]({self.full_scan_url})\n"
                valid_notifications.append({'title': item['title'], 'content': content})
            else:
                logger.warning('GithubPRNotifier: skipping invalid notification item: %s', type(item))
        
        if not valid_notifications:
            return

        # Get PR number for current branch
        pr_number = self._get_pr_number()
        if not pr_number:
            logger.warning('GithubPRNotifier: unable to determine PR number for current branch')
            return
        
        # Get existing comments to check for sections to update
        existing_comments = self._get_pr_comments(pr_number)
        
        # Group notifications by comment (find existing sections)
        comment_updates = {}
        new_sections = []
        
        for notification in valid_notifications:
            content = notification['content']
            section_match = self._extract_section_markers(content)
            
            if section_match:
                section_type = section_match['type']
                section_content = section_match['content']
                
                # Find existing comment with this section
                existing_comment = self._find_comment_with_section(existing_comments, section_type)
                
                if existing_comment:
                    # Update existing comment
                    comment_id = existing_comment['id']
                    if comment_id not in comment_updates:
                        comment_updates[comment_id] = existing_comment['body']
                    comment_updates[comment_id] = self._update_section_in_comment(
                        comment_updates[comment_id], section_type, content
                    )
                else:
                    # New section to add
                    new_sections.append(content)
            else:
                # No section markers, treat as new section
                new_sections.append(content)
        
        # Update existing comments with new section content
        for comment_id, updated_body in comment_updates.items():
            success = self._update_comment(pr_number, comment_id, updated_body)
            if success:
                logger.info('GithubPRNotifier: updated existing comment %s', comment_id)
            else:
                logger.error('GithubPRNotifier: failed to update comment %s', comment_id)
        
        # Create separate comments for each new section
        # Each scanner should get its own comment to avoid merging issues
        for section_content in new_sections:
            success = self._post_comment(pr_number, section_content)
            if success:
                logger.info('GithubPRNotifier: posted individual comment for section')
            else:
                logger.error('GithubPRNotifier: failed to post individual comment')

    def _send_pr_comment(self, facts: Dict[str, Any], title: str, content: str) -> None:
        """Send a single PR comment with title and content."""
        if not self.token:
            logger.warning('GithubPRNotifier: no GitHub token available')
            return

        # Get repository and branch info from config (discovered by main logic)
        owner_repo = self.repository
        branch = self.config.get('branch')
        
        if not self.repository or not branch:
            logger.warning('GithubPRNotifier: repository (%s) or branch (%s) not available in config', 
                         self.repository, branch)
            return

        # Find PR number
        pr_number = self._get_pr_number()
        if not pr_number:
            logger.info('GithubPRNotifier: no PR found for branch %s in %s', branch, self.repository)
            return

        # Create comment body with pre-formatted content
        uid = f"socket-security:{self.repository}:{branch}:{title.lower().replace(' ', '-')}"
        marker = f"<!-- {uid} -->"
        comment_body = f"{marker}\n\n### {title}\n\n{content}\n\n---\n*Generated by Socket Security*"
        
        # Post the comment
        success = self._post_comment(pr_number, comment_body)
        if success:
            logger.info('GithubPRNotifier: posted comment for "%s"', title)
        else:
            logger.error('GithubPRNotifier: failed to post comment for "%s"', title)

    def _get_pr_number(self) -> Optional[int]:
        """Get PR number from environment or API."""
        # Try environment variables first
        pr_env = get_github_pr_number()
        if pr_env and pr_env.isdigit():
            logger.info(f"GithubPRNotifier: Using PR number from environment: {pr_env}")
            return int(pr_env)
        
        logger.debug(f"GithubPRNotifier: No PR number in environment (GITHUB_PR_NUMBER: {pr_env or 'not set'})")
        
        # Try to find via API
        pr_number = self._find_pr_for_branch()
        if pr_number:
            logger.info(f"GithubPRNotifier: Found PR number via API: {pr_number}")
        else:
            logger.debug("GithubPRNotifier: Could not find PR number via API")
        
        return pr_number

    def _find_pr_for_branch(self) -> Optional[int]:
        """Find PR number for the given branch using API."""
        owner_repo = self.repository
        branch = self.config.get('branch')
        
        logger.debug(f"GithubPRNotifier: Searching for PR - repository: {owner_repo}, branch: {branch}")
        
        if not self.repository or not branch:
            logger.debug(f"GithubPRNotifier: Missing required info - repository: {bool(self.repository)}, branch: {bool(branch)}")
            return None
            
        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"{self.api_base}/repos/{self.repository}/pulls"
            params = {'head': f"{self.repository.split('/')[0]}:{branch}", 'state': 'open'}
            
            logger.debug(f"GithubPRNotifier: API request to {url} with params: {params}")
            
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                prs = resp.json()
                if prs:
                    logger.debug(f"GithubPRNotifier: Found {len(prs)} open PR(s) for branch {branch}")
                    return prs[0]['number']
                else:
                    logger.debug(f"GithubPRNotifier: No open PRs found for branch {branch}")
            else:
                logger.warning(f"GithubPRNotifier: API request failed with status {resp.status_code}")
        except Exception as e:
            logger.debug('GithubPRNotifier: failed to find PR for branch %s: %s', branch, e)
        
        return None

    def _get_pr_comments(self, pr_number: int) -> List[Dict[str, Any]]:
        """Get all comments for a PR."""
        owner_repo = self.repository
        
        if not self.repository:
            return []
            
        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"{self.api_base}/repos/{self.repository}/issues/{pr_number}/comments"
            
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning('GithubPRNotifier: failed to get comments: %s', resp.status_code)
                return []
        except Exception as e:
            logger.error('GithubPRNotifier: exception getting comments: %s', e)
            return []

    def _extract_section_markers(self, content: str) -> Optional[Dict[str, str]]:
        """Extract section type and content from HTML comment markers."""
        import re
        
        # Look for <!-- TYPE start --> ... <!-- TYPE end -->
        pattern = r'<!-- ([a-zA-Z0-9\-_]+) start -->(.*?)<!-- \1 end -->'
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            section_type = match.group(1)
            section_content = content  # Keep full content with markers
            return {'type': section_type, 'content': section_content}
        
        return None

    def _find_comment_with_section(self, comments: List[Dict[str, Any]], section_type: str) -> Optional[Dict[str, Any]]:
        """Find an existing comment that contains the given section type."""
        import re
        
        pattern = f'<!-- {re.escape(section_type)} start -->'
        
        for comment in comments:
            if re.search(pattern, comment.get('body', '')):
                return comment
        
        return None

    def _update_section_in_comment(self, comment_body: str, section_type: str, new_section_content: str) -> str:
        """Update a specific section within a comment body."""
        import re
        
        # Pattern to match the existing section
        pattern = f'<!-- {re.escape(section_type)} start -->.*?<!-- {re.escape(section_type)} end -->'
        
        # Replace the existing section with new content
        # Use a lambda to avoid regex replacement string interpretation issues
        updated_body = re.sub(pattern, lambda m: new_section_content, comment_body, flags=re.DOTALL)
        
        return updated_body

    def _truncate_comment_if_needed(self, comment_body: str, full_scan_url: Optional[str] = None) -> str:
        """Truncate comment if it exceeds GitHub's character limit.
        
        Args:
            comment_body: The comment body to check
            full_scan_url: Optional URL to the full scan results
            
        Returns:
            Potentially truncated comment body with a link to full results
        """
        if len(comment_body) <= GITHUB_COMMENT_MAX_LENGTH:
            return comment_body
        
        # Calculate space needed for truncation message
        truncation_msg = "\n\n---\n\n⚠️ **Results truncated due to size limits.**"
        if full_scan_url:
            truncation_msg += f"\n\n🔗 [View complete scan results in Socket Report]({full_scan_url})"
        else:
            truncation_msg += "\n\nThe complete results exceed GitHub's comment size limit."
        
        # Reserve space for the truncation message
        max_content_length = GITHUB_COMMENT_MAX_LENGTH - len(truncation_msg) - 100  # Extra buffer
        
        # Truncate at a reasonable boundary (try to break at newline)
        truncated = comment_body[:max_content_length]
        
        # Try to find the last complete line or section
        last_newline = truncated.rfind('\n')
        if last_newline > max_content_length * 0.8:  # If we find a newline in the last 20%
            truncated = truncated[:last_newline]
        
        logger.warning(
            f'GithubPRNotifier: comment truncated from {len(comment_body)} to {len(truncated)} characters'
        )
        
        return truncated + truncation_msg

    def _update_comment(self, pr_number: int, comment_id: int, comment_body: str) -> bool:
        """Update an existing comment."""
        owner_repo = self.repository
        
        if not self.repository:
            return False
        
        # Truncate if needed
        full_scan_url = getattr(self, 'full_scan_url', None)
        comment_body = self._truncate_comment_if_needed(comment_body, full_scan_url)
            
        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"{self.api_base}/repos/{self.repository}/issues/comments/{comment_id}"
            payload = {'body': comment_body}
            
            resp = requests.patch(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.debug('GithubPRNotifier: comment updated successfully')
                return True
            else:
                logger.warning('GithubPRNotifier: API error updating comment %s: %s', resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error('GithubPRNotifier: exception updating comment: %s', e)
            return False

    def _post_comment(self, pr_number: int, comment_body: str) -> bool:
        """Post a comment to the PR."""
        if not self.repository:
            logger.warning('GithubPRNotifier: no repository configured')
            return False
        
        # Truncate if needed
        full_scan_url = getattr(self, 'full_scan_url', None)
        comment_body = self._truncate_comment_if_needed(comment_body, full_scan_url)
            
        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            url = f"{self.api_base}/repos/{self.repository}/issues/{pr_number}/comments"
            payload = {'body': comment_body}
            
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 201:
                logger.debug('GithubPRNotifier: comment posted successfully')
                return True
            else:
                logger.warning('GithubPRNotifier: API error %s: %s', resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error('GithubPRNotifier: exception posting comment: %s', e)
            return False