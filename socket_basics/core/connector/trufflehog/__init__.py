#!/usr/bin/env python3
"""
TruffleHog Secret Scanner Connector
Handles TruffleHog execution and result processing
"""

import json
import logging
import subprocess
import os
from typing import Dict, List, Any

from ..base import BaseConnector

logger = logging.getLogger(__name__)


class TruffleHogScanner(BaseConnector):
    """TruffleHog secret scanner implementation"""
    
    def __init__(self, config):
        super().__init__(config)
    
    def is_enabled(self) -> bool:
        """Check if secret scanning should be enabled"""
        return self.config.get('secret_scanning_enabled', False)
    
    def scan(self) -> Dict[str, Any]:
        """Run Trufflehog secret scanning"""
        if not self.is_enabled():
            logger.info("Secret scanning disabled, skipping Trufflehog")
            return {}
        
        logger.info("Running Trufflehog secret scanning")
        
        targets = self.config.get_scan_targets()
        results = {}
        
        try:
            # Prefer explicit changed_files, fallback to git staged
            changed_files = self.config.get('changed_files', []) if hasattr(self.config, '_config') else []
            if not changed_files:
                try:
                    from socket_basics.core.config import _detect_git_changed_files
                    changed_files = _detect_git_changed_files(str(self.config.workspace), mode='staged')
                except Exception:
                    changed_files = []

            cmd = [
                'trufflehog',
                'filesystem',
                '--json',
                '--no-verification' if not self.config.get('trufflehog_show_unverified', False) else '--include-detectors=all'
            ]

            # Add exclusion patterns
            exclude_dirs = self.config.get('trufflehog_exclude_dir', '')
            if exclude_dirs:
                for exclude_dir in exclude_dirs.split(','):
                    cmd.extend(['--exclude-paths', exclude_dir.strip()])

            # If changed_files present, pass those individual files, otherwise use configured targets
            if changed_files:
                for cf in changed_files:
                    cmd.append(str(self.config.workspace / cf))
            else:
                cmd.extend(targets)
            
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

            return {'components': components_list, 'notifications': tables}
            
        except FileNotFoundError:
            logger.error("Trufflehog not found. Please install Trufflehog")
        except Exception as e:
            logger.error(f"Error running Trufflehog: {e}")
        
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
        from pathlib import Path

        # Group findings by file path so each file gets its own component.
        comps: Dict[str, Dict[str, Any]] = {}

        def _hash_file_or_path(file_path: str) -> str:
            try:
                p = Path(file_path)
                # resolve relative to workspace when available
                try:
                    ws = getattr(self.config, 'workspace', None)
                    if ws and not p.is_absolute():
                        p = Path(ws) / file_path
                    # If path is absolute and inside the workspace, make it relative
                    elif ws and p.is_absolute():
                        try:
                            ws_path = Path(getattr(ws, 'path', None) or getattr(ws, 'root', None) or str(ws))
                            if str(p).startswith(str(ws_path)):
                                p = Path(os.path.relpath(str(p), str(ws_path)))
                        except Exception:
                            pass
                except Exception:
                    pass
                # Use normalized posix path rather than file contents to avoid
                # reading files; this keeps IDs stable across runs and aligns
                # with the requested rule (sha256 of path+filename).
                norm = str(p.as_posix())
                return hashlib.sha256(norm.encode('utf-8')).hexdigest()
            except Exception:
                return hashlib.sha256((file_path or 'unknown').encode('utf-8')).hexdigest()

        for f in findings:
            fp = f.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file') or ''
            # normalize path
            try:
                # Normalize path first
                try:
                    fp = os.path.normpath(fp)
                except Exception:
                    pass

                # Attempt to strip workspace prefix whether the path is absolute
                # or a relative path that includes the workspace folder like
                # "../NodeGoat/...". This makes component names and alerts
                # consistent across environments.
                try:
                    workspace_root = getattr(self.config, 'workspace', None)
                    workspace_root = getattr(workspace_root, 'path', None) or getattr(workspace_root, 'root', None) or workspace_root
                    workspace_name = os.path.basename(workspace_root) if workspace_root else None
                    # If absolute and inside workspace, make relative
                    if workspace_root and os.path.isabs(fp):
                        try:
                            if str(fp).startswith(str(workspace_root)):
                                fp = os.path.normpath(os.path.relpath(fp, workspace_root))
                        except Exception:
                            pass
                    else:
                        # For relative paths like "../NodeGoat/..." or "NodeGoat/...",
                        # remove leading '../<workspace>' or './<workspace>' or '<workspace>'.
                        if workspace_name:
                            parts = fp.split(os.sep)
                            if parts and parts[0] == workspace_name:
                                parts = parts[1:]
                            elif len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == workspace_name:
                                parts = parts[2:]
                            if parts:
                                fp = os.path.join(*parts)
                            else:
                                fp = ''
                except Exception:
                    pass
            except Exception:
                pass

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
                    "qualifiers": {
                        "scanner": "secrets",
                        "type": inferred_type
                    },
                    "alerts": []
                }

            alert = self._create_alert(f)
            if alert:
                alert.setdefault('props', alert.get('props', {}) or {})
                alert['type'] = (alert.get('type', 'generic') or 'generic').lower()
                alert['severity'] = (alert.get('severity', '') or '').lower()
                alert.setdefault('category', 'supplyChainRisk')
                comps[comp_id]['alerts'].append(alert)

        return comps
    
    def _create_alert(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a generic alert from a Trufflehog finding"""
        detector_name = finding.get('DetectorName', 'unknown')
        verified = finding.get('Verified', False)
        file_path = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown')
        line = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0)

        # Verified secrets are critical; unverified findings are low severity
        severity = 'critical' if verified else 'low'

        # Make file paths relative to workspace root when possible
        # Normalize and strip workspace prefix similar to above so alerts
        # display paths without the workspace folder.
        try:
            file_path = os.path.normpath(file_path)
        except Exception:
            pass

        try:
            workspace_root = getattr(self.config.workspace, 'path', None) or getattr(self.config.workspace, 'root', None)
        except Exception:
            workspace_root = None

        try:
            if workspace_root and file_path and os.path.isabs(file_path):
                file_path = os.path.normpath(os.path.relpath(file_path, workspace_root))
            else:
                # remove leading workspace folder for relative paths like
                # "../NodeGoat/..." or "NodeGoat/..."
                workspace_name = os.path.basename(workspace_root) if workspace_root else None
                if workspace_name:
                    parts = file_path.split(os.sep)
                    if parts and parts[0] == workspace_name:
                        parts = parts[1:]
                    elif len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == workspace_name:
                        parts = parts[2:]
                    file_path = os.path.join(*parts) if parts else file_path
                else:
                    file_path = os.path.normpath(file_path)
        except Exception:
            pass

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
                "detectorName": detector_name,
                "verified": verified,
                "filePath": file_path,
                "lineNumber": line,
                "secretType": detector_name.lower(),
                "redactedValue": redacted_secret,
                "isActive": verified,
                "riskLevel": "critical" if verified else "low",
                "exposureType": "source-code",
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }

    # Notification processor for TruffleHog secrets
    def notification_rows(self, processed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return a list of canonical notification table dicts.

        Each table dict must include a `title`, optional `headers`, and `rows`.
        Example:
          [{"title": "Secrets", "headers": [...], "rows": [[...], ...]}]
        """
        rows: List[List[str]] = []
        for comp in processed_results.values():
            for a in comp.get('alerts', []):
                props = a.get('props', {}) or {}
                detection = props.get('detectorName', '') or a.get('title') or ''
                sev = a.get('severity', '')
                file_path = props.get('filePath', '-')
                line = props.get('lineNumber', '')
                redacted = props.get('redactedValue', '')
                # Build row as: Detection, Severity, File, Line, Secrets (redacted)
                rows.append([detection, sev, file_path, f"{line}" if line else '-', redacted])

        table = {
            'title': 'Secrets',
            'headers': ['Detection', 'Severity', 'File', 'Line', 'Secrets'],
            'rows': rows,
        }

        # Return empty list when there are no rows to make callers skip it cleanly
        return [table] if rows else []
