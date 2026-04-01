from typing import Any, Dict, List, Optional
import logging
from urllib.parse import quote

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
        labels_enabled = self.config.get('pr_labels_enabled', True)
        
        if not isinstance(notifications, list):
            logger.error('GithubPRNotifier: only supports new format - list of dicts with title/content')
            return

        # Get full scan URL if available and store it for use in truncation
        self.full_scan_url = facts.get('full_scan_html_url')

        # Validate format
        valid_notifications = []
        for item in notifications:
            if isinstance(item, dict) and 'title' in item and 'content' in item:
                # Full scan URL is now handled in the formatter itself
                valid_notifications.append({'title': item['title'], 'content': item['content']})
            else:
                logger.warning('GithubPRNotifier: skipping invalid notification item: %s', type(item))

        if not valid_notifications:
            if labels_enabled:
                pr_number = self._get_pr_number()
                if pr_number:
                    self._reconcile_pr_labels(pr_number, [])
                    self._replace_existing_sections_with_all_clear(pr_number)
                else:
                    logger.warning('GithubPRNotifier: unable to determine PR number for label reconciliation')
            logger.info('GithubPRNotifier: no notifications present; skipping comments')
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

        # Add labels to PR if enabled
        if labels_enabled and pr_number:
            labels = self._determine_pr_labels(valid_notifications)
            self._reconcile_pr_labels(pr_number, labels)
    def _managed_pr_label_config(self) -> Dict[str, str]:
        """Return the managed severity label names configured for PRs."""
        return {
            'critical': self.config.get('pr_label_critical', 'security: critical'),
            'high': self.config.get('pr_label_high', 'security: high'),
            'medium': self.config.get('pr_label_medium', 'security: medium'),
            'low': self.config.get('pr_label_low', 'security: low'),
        }

    def _get_label_color_info(self, label: str) -> Optional[tuple[str, str]]:
        """Infer color/description for managed or custom severity labels."""
        label_colors = {
            self.config.get('pr_label_critical', 'security: critical'): ('D73A4A', 'Critical security vulnerabilities'),
            self.config.get('pr_label_high', 'security: high'): ('D93F0B', 'High severity security issues'),
            self.config.get('pr_label_medium', 'security: medium'): ('FBCA04', 'Medium severity security issues'),
            self.config.get('pr_label_low', 'security: low'): ('E4E4E4', 'Low severity security issues'),
        }
        color_info = label_colors.get(label)
        if color_info:
            return color_info

        label_lower = label.lower()
        if 'critical' in label_lower:
            return ('D73A4A', 'Critical security vulnerabilities')
        if 'high' in label_lower:
            return ('D93F0B', 'High severity security issues')
        if 'medium' in label_lower:
            return ('FBCA04', 'Medium severity security issues')
        if 'low' in label_lower:
            return ('E4E4E4', 'Low severity security issues')
        return None


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

    def _extract_all_section_types(self, comment_body: str) -> List[str]:
        """Extract all managed section markers from a comment body."""
        import re

        pattern = r'<!-- ([a-zA-Z0-9\-_]+) start -->'
        return re.findall(pattern, comment_body or '')

    def _extract_section_title(self, section_content: str) -> str:
        """Extract the display title from a wrapped PR comment section."""
        import re

        for line in (section_content or '').splitlines():
            stripped = line.strip()
            if stripped.startswith('## '):
                title = stripped[3:].strip()
                title = re.sub(r'<img[^>]+>\s*', '', title).strip()
                return title or 'Socket Security'
        return 'Socket Security'

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

    def _build_all_clear_section(self, section_type: str, existing_section_content: str) -> str:
        """Build an all-clear replacement for an existing managed section."""
        from socket_basics.core.notification import github_pr_helpers as helpers

        title = self._extract_section_title(existing_section_content)
        body = "✅ Socket Basics found no active findings in the latest run."
        return helpers.wrap_pr_comment_section(section_type, title, body, self.full_scan_url)

    def _replace_existing_sections_with_all_clear(self, pr_number: int) -> None:
        """Rewrite existing managed PR comment sections to an all-clear state."""
        existing_comments = self._get_pr_comments(pr_number)
        for comment in existing_comments:
            original_body = comment.get('body', '')
            if not original_body:
                continue

            updated_body = original_body
            changed = False
            for section_type in self._extract_all_section_types(original_body):
                section_match = self._extract_section_markers(updated_body)
                if not section_match or section_match.get('type') != section_type:
                    import re
                    pattern = rf'<!-- {re.escape(section_type)} start -->.*?<!-- {re.escape(section_type)} end -->'
                    match = re.search(pattern, updated_body, re.DOTALL)
                    if not match:
                        continue
                    section_content = match.group(0)
                else:
                    section_content = section_match['content']

                all_clear_section = self._build_all_clear_section(section_type, section_content)
                next_body = self._update_section_in_comment(updated_body, section_type, all_clear_section)
                if next_body != updated_body:
                    updated_body = next_body
                    changed = True

            if changed:
                success = self._update_comment(pr_number, comment['id'], updated_body)
                if success:
                    logger.info('GithubPRNotifier: updated existing comment %s to all-clear state', comment['id'])
                else:
                    logger.error('GithubPRNotifier: failed to update comment %s to all-clear state', comment['id'])

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

    def _ensure_label_exists_with_color(self, label_name: str, color: str, description: str = '') -> bool:
        """Ensure a label exists in the repository with the specified color.

        If the label doesn't exist, it will be created with the given color.
        If it already exists, we leave it alone (don't update existing labels).

        Args:
            label_name: Name of the label
            color: Hex color code (without #), e.g., 'D73A4A'
            description: Optional description for the label

        Returns:
            True if label exists/was created, False otherwise
        """
        if not self.repository:
            return False

        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            # Check if label exists
            check_url = f"{self.api_base}/repos/{self.repository}/labels/{label_name}"
            resp = requests.get(check_url, headers=headers, timeout=10)

            if resp.status_code == 200:
                # Label already exists, don't modify it
                logger.debug('GithubPRNotifier: label "%s" already exists', label_name)
                return True
            elif resp.status_code == 404:
                # Label doesn't exist, create it
                create_url = f"{self.api_base}/repos/{self.repository}/labels"
                payload = {
                    'name': label_name,
                    'color': color,
                    'description': description
                }

                create_resp = requests.post(create_url, headers=headers, json=payload, timeout=10)
                if create_resp.status_code == 201:
                    logger.info('GithubPRNotifier: created label "%s" with color #%s', label_name, color)
                    return True
                else:
                    logger.warning(
                        'GithubPRNotifier: failed to create label "%s": %s %s',
                        label_name,
                        create_resp.status_code,
                        create_resp.text[:200],
                    )
                    return False
            else:
                logger.warning(
                    'GithubPRNotifier: unexpected response checking label "%s": %s %s',
                    label_name,
                    resp.status_code,
                    resp.text[:200],
                )
                return False

        except Exception as e:
            logger.debug('GithubPRNotifier: exception ensuring label exists: %s', e)
            return False

    def _ensure_pr_labels_exist(self, labels: List[str]) -> None:
        """Ensure desired labels exist in the repository with appropriate colors."""
        for label in labels:
            color_info = self._get_label_color_info(label)
            if color_info:
                color, description = color_info
                self._ensure_label_exists_with_color(label, color, description)

    def _get_current_pr_label_names(self, pr_number: int) -> List[str]:
        """Fetch current label names for the PR."""
        if not self.repository:
            return []

        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            url = f"{self.api_base}/repos/{self.repository}/issues/{pr_number}/labels"
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                payload = resp.json()
                return [label.get('name') for label in payload if isinstance(label, dict) and label.get('name')]
            logger.warning(
                'GithubPRNotifier: failed to fetch current labels for PR %s: %s %s',
                pr_number,
                resp.status_code,
                resp.text[:200],
            )
        except Exception as e:
            logger.error('GithubPRNotifier: exception fetching current labels: %s', e)
        return []

    def _remove_pr_label(self, pr_number: int, label: str) -> bool:
        """Remove a label from a PR."""
        if not self.repository or not label:
            return False

        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            encoded_label = quote(label, safe='')
            url = f"{self.api_base}/repos/{self.repository}/issues/{pr_number}/labels/{encoded_label}"
            resp = requests.delete(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                logger.info('GithubPRNotifier: removed label from PR %s: %s', pr_number, label)
                return True
            if resp.status_code == 404:
                logger.debug('GithubPRNotifier: label %s already absent from PR %s', label, pr_number)
                return True
            logger.warning(
                'GithubPRNotifier: failed to remove label "%s" from PR %s: %s %s',
                label,
                pr_number,
                resp.status_code,
                resp.text[:200],
            )
        except Exception as e:
            logger.error('GithubPRNotifier: exception removing label %s: %s', label, e)
        return False

    def _add_pr_labels(self, pr_number: int, labels: List[str]) -> bool:
        """Add missing labels to a PR.

        Args:
            pr_number: PR number
            labels: List of label names to add

        Returns:
            True if successful, False otherwise
        """
        if not self.repository or not labels:
            return False

        try:
            import requests
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            url = f"{self.api_base}/repos/{self.repository}/issues/{pr_number}/labels"
            payload = {'labels': labels}

            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info('GithubPRNotifier: added labels to PR %s: %s', pr_number, ', '.join(labels))
                return True
            else:
                logger.warning('GithubPRNotifier: failed to add labels: %s %s', resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error('GithubPRNotifier: exception adding labels: %s', e)
            return False

    def _reconcile_pr_labels(self, pr_number: int, desired_labels: List[str]) -> bool:
        """Reconcile managed severity labels on the PR to match the latest run."""
        managed_labels = set(filter(None, self._managed_pr_label_config().values()))
        current_labels = set(self._get_current_pr_label_names(pr_number))
        desired_label_set = set(filter(None, desired_labels))

        stale_labels = sorted(label for label in current_labels if label in managed_labels and label not in desired_label_set)
        labels_to_add = sorted(label for label in desired_label_set if label not in current_labels)

        success = True
        for label in stale_labels:
            success = self._remove_pr_label(pr_number, label) and success

        if labels_to_add:
            self._ensure_pr_labels_exist(labels_to_add)
            success = self._add_pr_labels(pr_number, labels_to_add) and success

        if not stale_labels and not labels_to_add:
            logger.info('GithubPRNotifier: PR %s severity labels already up to date', pr_number)
        return success

    def _determine_pr_labels(self, notifications: List[Dict[str, Any]]) -> List[str]:
        """Determine which labels to add based on notifications.

        Args:
            notifications: List of notification dictionaries

        Returns:
            List of label names to add
        """
        severities_found = set()

        # Scan notifications for severity indicators
        for notif in notifications:
            content = notif.get('content', '')

            # Look for severity indicators in content
            # Pattern: "Critical: X" where X > 0
            import re
            critical_match = re.search(r'Critical:\s*(\d+)', content)
            high_match = re.search(r'High:\s*(\d+)', content)
            medium_match = re.search(r'Medium:\s*(\d+)', content)
            low_match = re.search(r'Low:\s*(\d+)', content)

            if critical_match and int(critical_match.group(1)) > 0:
                severities_found.add('critical')
            if high_match and int(high_match.group(1)) > 0:
                severities_found.add('high')
            if medium_match and int(medium_match.group(1)) > 0:
                severities_found.add('medium')
            if low_match and int(low_match.group(1)) > 0:
                severities_found.add('low')

        # Map severities to label names (using configurable labels)
        labels = []
        if 'critical' in severities_found:
            label_name = self.config.get('pr_label_critical', 'security: critical')
            labels.append(label_name)
        elif 'high' in severities_found:
            label_name = self.config.get('pr_label_high', 'security: high')
            labels.append(label_name)
        elif 'medium' in severities_found:
            label_name = self.config.get('pr_label_medium', 'security: medium')
            labels.append(label_name)
        elif 'low' in severities_found:
            label_name = self.config.get('pr_label_low', 'security: low')
            labels.append(label_name)

        return labels