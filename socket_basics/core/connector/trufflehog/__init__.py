#!/usr/bin/env python3
"""
TruffleHog Secret Scanner Connector
Handles TruffleHog execution and result processing
"""

import json
import logging
import os
import posixpath
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any

from ..base import BaseConnector

# coerce_bool lives in the config layer because the environment loader, a
# Socket dashboard config, and a JSON config each deliver booleans differently.
from ...config import coerce_bool

# Import individual notifier modules
from . import github_pr, slack, ms_teams, ms_sentinel, sumologic, console, jira, webhook, json_notifier

# Import shared formatters
from ...formatters import get_all_formatters

logger = logging.getLogger(__name__)


class TruffleHogScanner(BaseConnector):
    """TruffleHog secret scanner implementation"""
    
    def __init__(self, config):
        super().__init__(config)
    
    def is_enabled(self) -> bool:
        """Check if secret scanning should be enabled"""
        return self.config.get('secret_scanning_enabled', False)
    
    @staticmethod
    def _path_regex(value: str) -> str:
        """Escape a filesystem path for TruffleHog's Go regular-expression input."""
        normalized = str(value).replace('\\', '/')
        return re.escape(normalized).replace('/', r'[/\\]')

    @staticmethod
    def _glob_regex(value: str) -> str:
        """Translate a path glob into a TruffleHog-compatible regex.

        TruffleHog consumes Go/RE2 regexes, not shell globs. Keep ``*`` and
        ``?`` within a path segment, and let ``**/`` span zero or more path
        segments. All other characters are treated literally.
        """
        normalized = str(value).replace('\\', '/').strip('/')
        pieces = []
        index = 0
        while index < len(normalized):
            char = normalized[index]
            if char == '*':
                if index + 1 < len(normalized) and normalized[index + 1] == '*':
                    index += 2
                    if index < len(normalized) and normalized[index] == '/':
                        pieces.append(r'(?:.*[/\\])?')
                        index += 1
                    else:
                        pieces.append(r'.*')
                    continue
                pieces.append(r'[^/\\]*')
            elif char == '?':
                pieces.append(r'[^/\\]')
            elif char == '/':
                pieces.append(r'[/\\]')
            else:
                pieces.append(re.escape(char))
            index += 1
        return ''.join(pieces)

    def _workspace_root(self) -> str:
        """Return the absolute workspace path used by the scanner command."""
        workspace = getattr(self.config, 'workspace', None)
        if not isinstance(workspace, (str, bytes, os.PathLike)):
            workspace = (
                getattr(workspace, 'path', None)
                or getattr(workspace, 'root', None)
                or workspace
            )
        if not workspace:
            return ''
        try:
            root = os.path.abspath(os.fspath(workspace))
            return root if root in ('/', '\\') else root.rstrip('/\\')
        except (TypeError, ValueError):
            return ''

    def _workspace_relative_path(self, file_path: Any) -> str:
        """Return a finding path relative to the configured workspace."""
        if not file_path:
            return ''
        try:
            path = os.path.normpath(os.fspath(file_path))
        except (TypeError, ValueError):
            path = os.path.normpath(str(file_path))

        workspace_root = self._workspace_root()
        if not workspace_root or not path:
            return path

        try:
            candidate = (
                os.path.abspath(path)
                if os.path.isabs(path)
                else os.path.abspath(os.path.join(workspace_root, path))
            )
            if os.path.commonpath([workspace_root, candidate]) == workspace_root:
                return os.path.normpath(os.path.relpath(candidate, workspace_root))
        except (OSError, ValueError):
            pass

        return path

    def _build_exclude_patterns(self, exclude_dirs: Any) -> List[str]:
        """Build workspace-relative path patterns for TruffleHog.

        TruffleHog expects one --exclude-paths value containing a file of
        newline-separated regular expressions. The configured values are
        directory names, so anchor each one below the workspace root. This
        prevents a directory such as tmp from matching the workspace's
        parent path (for example /tmp/...), and prevents .git from
        matching .github.
        """
        if isinstance(exclude_dirs, str):
            entries = exclude_dirs.split(',')
        else:
            entries = exclude_dirs or []

        workspace_root = self._workspace_root()
        patterns = []
        for entry in entries:
            directory = posixpath.normpath(
                str(entry).strip().replace('\\', '/')
            ).strip('/')
            if directory in ('', '.'):
                continue

            has_glob = '*' in directory or '?' in directory
            if has_glob:
                directory_regex = self._glob_regex(directory)
            else:
                directory_regex = self._path_regex(directory)

            # A pattern without a slash is a basename/segment pattern and
            # should work at any depth below the workspace. Patterns with a
            # slash stay root-relative unless they explicitly use ``**/``.
            if '/' not in directory:
                directory_regex = rf'(?:[^/\\]+[/\\])*{directory_regex}'

            if workspace_root:
                root_regex = self._path_regex(workspace_root)
                root_separator = '' if workspace_root in ('/', '\\') else r'[/\\]'
                patterns.append(
                    rf'^{root_regex}{root_separator}{directory_regex}(?:[/\\]|$)'
                )
            else:
                patterns.append(rf'(?:^|[/\\]){directory_regex}(?:[/\\]|$)')

        return patterns

    def _write_exclude_file(self, exclude_dirs: Any) -> str | None:
        """Write exclude regexes to a temporary file for TruffleHog."""
        patterns = self._build_exclude_patterns(exclude_dirs)
        return self._write_exclude_patterns(patterns)

    def _write_exclude_patterns(self, patterns: List[str]) -> str | None:
        """Write resolved exclude regexes to a temporary file."""
        if not patterns:
            return None

        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            prefix='socket-basics-trufflehog-',
            suffix='.txt',
            delete=False,
        ) as exclude_file:
            exclude_file.write('\n'.join(patterns))
            exclude_file.write('\n')
            return exclude_file.name

    @staticmethod
    def _absolute_scan_target(target: Any) -> str:
        """Return the absolute path string TruffleHog will filter against."""
        return os.path.abspath(os.fspath(target))

    @staticmethod
    def _path_matches_patterns(path: str, patterns: List[str]) -> bool:
        """Return whether a path matches one of the generated exclude patterns."""
        return any(re.search(pattern, path) for pattern in patterns)

    def _warn_if_target_outside_workspace(self, target: str) -> None:
        """Warn when workspace-anchored excludes cannot apply to a target."""
        workspace_root = self._workspace_root()
        if not workspace_root:
            return
        try:
            inside_workspace = os.path.commonpath([workspace_root, target]) == workspace_root
        except (OSError, ValueError):
            inside_workspace = False
        if not inside_workspace:
            logger.warning(
                "TruffleHog scan target %s is outside workspace %s; configured excludes may not apply",
                target,
                workspace_root,
            )

    def _existing_changed_file_paths(self, changed_files: List[str]) -> List[str]:
        """Resolve changed paths against the workspace, dropping ones that are gone.

        A changed-file list routinely names paths that are no longer on disk:
        a delete-only PR, the old half of a rename, a file the branch removed
        later on. TruffleHog exits non-zero on a path it cannot open, which
        throws away the findings for every other path in the same run, so the
        missing ones have to go before the command is built. This is the rule
        ``Config._resolve_file_targets`` already applies for the scanners that
        take their targets from ``get_scan_targets()``; the list here does not
        pass through it, because it can also come from the staged-file fallback.
        """
        workspace_root = Path(self._workspace_root())
        resolved: List[str] = []
        for changed_file in changed_files:
            path = Path(changed_file)
            if not path.is_absolute():
                path = workspace_root / changed_file
            if path.exists():
                resolved.append(str(path))
            else:
                logger.info("Skipping changed file that no longer exists: %s", path)
        return resolved

    def scan(self) -> Dict[str, Any]:
        """Run Trufflehog secret scanning"""
        if not self.is_enabled():
            logger.info("Secret scanning disabled, skipping Trufflehog")
            return {}
        
        logger.info("Running Trufflehog secret scanning")
        
        targets = self.config.get_scan_targets()
        results = {}

        exclude_file_path = None
        exclude_patterns: List[str] = []
        try:
            # Prefer explicit changed_files, falling back to git staged only
            # when neither a changed-files scope nor scan_all was requested. A
            # successful scope that resolved empty must stay empty; after a
            # failed resolution, scan_all must use the workspace target rather
            # than an incidental staged-file scope.
            changed_files = self.config.get('changed_files', []) if hasattr(self.config, '_config') else []
            scope_requested = self._changed_files_scope_requested()
            if (
                not changed_files
                and not scope_requested
                and not self.config.get('scan_all', False)
            ):
                try:
                    from socket_basics.core.config import _detect_git_changed_files
                    changed_files = _detect_git_changed_files(str(self.config.workspace), mode='staged')
                except Exception:
                    changed_files = []

            # Verification always runs so that findings carry a trustworthy
            # Verified flag; the setting only controls which result types are
            # returned. Detector selection is deliberately independent of it.
            #
            # coerce_bool, not truthiness: only the environment loader coerces
            # bool params, while a Socket dashboard config is passed through
            # verbatim at higher priority. A dashboard-supplied string "false"
            # is truthy, and reading it as "on" would report unverified secrets
            # to someone who explicitly asked for verified-only.
            show_unverified = coerce_bool(
                self.config.get('trufflehog_show_unverified'), False
            )
            results_filter = (
                'verified,unverified,unknown' if show_unverified else 'verified'
            )

            cmd = [
                'trufflehog',
                'filesystem',
                '--json',
                '--include-detectors=all',
                f'--results={results_filter}',
            ]

            # TruffleHog accepts --exclude-paths only once and expects a file
            # containing newline-separated regular expressions.
            exclude_dirs = self.config.get('trufflehog_exclude_dir', '')
            if exclude_dirs:
                exclude_patterns = self._build_exclude_patterns(exclude_dirs)
                logger.debug("TruffleHog exclude patterns: %s", exclude_patterns)
                exclude_file_path = self._write_exclude_patterns(exclude_patterns)
                if exclude_file_path:
                    cmd.extend(['--exclude-paths', exclude_file_path])

            # If changed_files are present, pass those individual files;
            # otherwise use the configured targets (including scan_files).
            if changed_files or scope_requested:
                target_candidates = self._existing_changed_file_paths(changed_files)
                excluded_target_message = "Skipping excluded changed file: %s"
                all_excluded_message = "All changed files were excluded from TruffleHog scanning"
            else:
                target_candidates = list(targets or [])
                excluded_target_message = "Skipping excluded scan target: %s"
                all_excluded_message = "All scan targets were excluded from TruffleHog scanning"

            scan_targets = []
            for candidate in target_candidates:
                target = self._absolute_scan_target(candidate)
                self._warn_if_target_outside_workspace(target)
                if exclude_patterns and self._path_matches_patterns(target, exclude_patterns):
                    logger.info(excluded_target_message, target)
                    continue
                scan_targets.append(target)

            if not scan_targets:
                if target_candidates:
                    logger.info(all_excluded_message)
                else:
                    logger.info("No TruffleHog scan targets found; skipping")
                return results
            cmd.extend(scan_targets)
            
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Trufflehog failed: {result.stderr}")
                return {}
            
            # Parse JSON output line by line
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse Trufflehog output line: {line}")

            # Convert raw processed mapping -> canonical wrapper and attach
            # connector-produced notification tables. Connectors are expected
            # to produce presentation-ready notification tables via
            # `notification_rows`.
            raw_processed = self._process_results(findings)

            # Accept either a mapping id->component or a canonical wrapper
            if isinstance(raw_processed, dict) and raw_processed and 'components' in raw_processed and isinstance(raw_processed.get('components'), list):
                components_list = raw_processed.get('components', [])
                mapping = {c.get('id') or c.get('name') or str(id(c)): c for c in components_list}
            elif isinstance(raw_processed, dict):
                # mapping id->component
                mapping = raw_processed
                components_list = list(mapping.values())
            else:
                mapping = {}
                components_list = []

            # Connector-level notification tables (preferred)
            try:
                tables = self.notification_rows(mapping)
            except Exception:
                tables = []

            # Fallback: if connector did not return structured tables, try
            # to synthesize a simple 'results' table from alerts
            if not tables:
                notifications = []
                for c in components_list:
                    cid = c.get('id') or c.get('name') or ''
                    for a in c.get('alerts', []) or []:
                        path = (a.get('props') or {}).get('filePath') or (a.get('location') or {}).get('path') or c.get('name') or cid
                        line = (a.get('props') or {}).get('startLine') or (a.get('location') or {}).get('line') or ''
                        notifications.append([cid, str(a.get('severity') or ''), a.get('title') or a.get('description') or '', f"{path}:{line}" if line else (path or '')])
                if notifications:
                    tables = [{'title': 'results', 'headers': ['component','severity','title','location'], 'rows': notifications}]

            # Build notifications using new shared formatters
            notifications_by_notifier = self.generate_notifications(components_list)
            
            # return Socket facts format
            return {
                'components': components_list,
                'notifications': notifications_by_notifier
            }
            
        except FileNotFoundError:
            logger.error("Trufflehog not found. Please install Trufflehog")
        except Exception as e:
            logger.error(f"Error running Trufflehog: {e}")
        finally:
            if exclude_file_path:
                try:
                    os.unlink(exclude_file_path)
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.warning(f"Failed to remove Trufflehog exclude file: {e}")

        return results
    
    def _convert_to_socket_facts(self, raw_results: Any) -> Dict[str, Any]:
        """Convert raw TruffleHog results to Socket facts format
        
        This method implements the BaseConnector interface
        """
        return self._process_results(raw_results)
    
    def _process_results(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert Trufflehog results to Socket facts format"""
        if not findings:
            return {}
        
        import hashlib

        # Group findings by file path so each file gets its own component.
        comps: Dict[str, Dict[str, Any]] = {}

        def _hash_file_or_path(file_path: str) -> str:
            try:
                # Use normalized posix path rather than file contents to avoid
                # reading files; this keeps IDs stable across runs and aligns
                # with the requested rule (sha256 of path+filename).
                norm = (
                    posixpath.normpath(str(file_path).replace('\\', '/'))
                    if file_path
                    else 'unknown'
                )
                return hashlib.sha256(norm.encode('utf-8')).hexdigest()
            except Exception:
                return hashlib.sha256((file_path or 'unknown').encode('utf-8')).hexdigest()

        for f in findings:
            fp = f.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file') or ''
            fp = self._workspace_relative_path(fp)

            comp_id = _hash_file_or_path(fp)

            if comp_id not in comps:
                # infer type from file extension
                inferred_type = 'source-code'
                try:
                    _, ext = os.path.splitext(fp)
                    if ext:
                        inferred_type = ext.lstrip('.').lower()
                except Exception:
                    pass

                comps[comp_id] = {
                    "id": comp_id,
                    "type": "generic",
                    "name": fp or 'Secret Scanning',
                    "internal": True,
                    "version": "",
                    "subpath": fp or 'trufflehog-analysis',
                    "direct": True,
                    "dev": False,
                    "dead": False,
                    "dependencies": [],
                    "manifestFiles": [{"file": fp}] if fp else [],
                    "subPath": "secret-scanning",
                    "alerts": []
                }

            alert = self._create_alert(f)
            if alert:
                alert.setdefault('props', alert.get('props', {}) or {})
                alert['type'] = (alert.get('type', 'generic') or 'generic').lower()
                alert['severity'] = (alert.get('severity', '') or '').lower()
                alert.setdefault('category', 'supplyChainRisk')
                comps[comp_id]['alerts'].append(alert)

        # Convert to Socket facts format
        components_list = list(comps.values())
        
        # Build notifications for all notifier types
        notifications_by_notifier = self.generate_notifications(components_list)
        
        return {
            'components': components_list,
            'notifications': notifications_by_notifier
        }
    
    def _create_alert(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a generic alert from a Trufflehog finding"""
        detector_name = finding.get('DetectorName', 'unknown')
        verified = finding.get('Verified', False)
        file_path = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown')
        line = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0)

        # Verified secrets are critical; unverified findings are low severity
        severity = 'critical' if verified else 'low'

        file_path = self._workspace_relative_path(file_path)

        # Redact the actual secret
        raw_secret = finding.get('Raw', '')
        redacted_secret = raw_secret[:4] + '*' * (len(raw_secret) - 8) + raw_secret[-4:] if len(raw_secret) > 8 else '*' * len(raw_secret)
    
        markdown_content = f"""## Secret Detected: {detector_name}

### Detection Details
- **File**: `{file_path}`
- **Line**: {line}
- **Detector**: {detector_name}
- **Verified**: {"✅ Yes" if verified else "❌ No"}
- **Redacted Value**: `{redacted_secret}`

### Risk Assessment
{"**CRITICAL**: This secret has been verified and is likely active!" if verified else "**LOW**: This appears to be a potential secret but has not been verified."}

### Immediate Actions Required
1. **Rotate the credential immediately**
2. **Remove from source code**
3. **Use environment variables or secret management**
4. **Audit access logs for potential misuse**

### Prevention Measures
```bash
# Add to .gitignore
echo "*.env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

# Use environment variables
export SECRET_KEY="your-secret-here"
```

### Secret Management Solutions
- **AWS Secrets Manager**: For AWS environments
- **Azure Key Vault**: For Azure environments  
- **HashiCorp Vault**: For on-premise solutions
- **GitHub Secrets**: For CI/CD pipelines
    """

        return {
            "type": "generic",
            "severity": severity,
            "title": f"Secret Exposed: {detector_name}",
            "description": f"Potential {detector_name} secret detected in source code",
            "category": "supplyChainRisk",
            "generatedBy": "trufflehog",
            "subType": "secrets",
            "action": self.config.get_action_for_severity(severity),
            "props": {
                "ruleId": detector_name,
                "verified": verified,
                "filePath": file_path,
                "lineNumber": line,
                "secretType": detector_name.lower(),
                "redactedValue": redacted_secret,
                "riskLevel": "critical" if verified else "low",
                "exposureType": "source-code",
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }




    # Notification processor for TruffleHog secrets
    def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
        """Legacy method - returns flat list of rows (not grouped tables).
        
        This is kept for backward compatibility.
        """
        rows: List[List[str]] = []
        if not processed_results:
            return rows
        
        # Handle new Socket facts format (with 'components' key)
        components = processed_results.get('components', [])
        if components and isinstance(components, list):
            for comp in components:
                for a in comp.get('alerts', []):
                    props = a.get('props', {}) or {}
                    detection = str(props.get('detectorName', '') or a.get('title') or '')
                    sev = str(a.get('severity', ''))
                    file_path = str(props.get('filePath', '-'))
                    line = str(props.get('lineNumber', ''))
                    redacted = str(props.get('redactedValue', ''))
                    # Build row as: Detection, Severity, File, Line, Secrets (redacted)
                    rows.append([detection, sev, file_path, f"{line}" if line else '-', redacted])
        else:
            # Handle old format (direct component mapping)
            for comp in processed_results.values():
                if hasattr(comp, 'get'):  # It's a dict
                    for a in comp.get('alerts', []):
                        props = a.get('props', {}) or {}
                        detection = str(props.get('detectorName', '') or a.get('title') or '')
                        sev = str(a.get('severity', ''))
                        file_path = str(props.get('filePath', '-'))
                        line = str(props.get('lineNumber', ''))
                        redacted = str(props.get('redactedValue', ''))
                        # Build row as: Detection, Severity, File, Line, Secrets (redacted)
                        rows.append([detection, sev, file_path, f"{line}" if line else '-', redacted])

        return rows
    
    def generate_notifications(self, components: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
        """Generate pre-formatted notifications for all notifier types.
        
        Args:
            components: List of component dictionaries with alerts
            
        Returns:
            Dictionary mapping notifier keys to lists of notification dictionaries
        """
        if not components:
            return {}
        
        # Create component mapping for compatibility with TruffleHog-specific formatters
        comps_map = {c.get('id') or c.get('name') or str(id(c)): c for c in components}
        
        # Filter components by severity
        filtered_comps_map = {}
        for comp_id, comp in comps_map.items():
            filtered_alerts = []
            for alert in comp.get('alerts', []):
                # Filter by severity - only include alerts that match allowed severities
                alert_severity = (alert.get('severity') or '').strip().lower()
                if alert_severity and hasattr(self, 'allowed_severities') and alert_severity not in self.allowed_severities:
                    continue  # Skip this alert - severity not enabled
                filtered_alerts.append(alert)
            
            # Only include component if it has filtered alerts
            if filtered_alerts:
                filtered_comp = comp.copy()
                filtered_comp['alerts'] = filtered_alerts
                filtered_comps_map[comp_id] = filtered_comp
        
        if not filtered_comps_map:
            return {}
        
        # Build notifications for each notifier type using TruffleHog-specific modules
        notifications_by_notifier = {}
        notifications_by_notifier['github_pr'] = github_pr.format_notifications(filtered_comps_map, config=self.config)
        notifications_by_notifier['slack'] = slack.format_notifications(filtered_comps_map)
        notifications_by_notifier['msteams'] = ms_teams.format_notifications(filtered_comps_map)
        notifications_by_notifier['ms_sentinel'] = ms_sentinel.format_notifications(filtered_comps_map)
        notifications_by_notifier['sumologic'] = sumologic.format_notifications(filtered_comps_map)
        notifications_by_notifier['json'] = json_notifier.format_notifications(filtered_comps_map)
        notifications_by_notifier['console'] = console.format_notifications(filtered_comps_map)
        notifications_by_notifier['jira'] = jira.format_notifications(filtered_comps_map)
        notifications_by_notifier['webhook'] = webhook.format_notifications(filtered_comps_map)
        
        return notifications_by_notifier
