import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from copy import deepcopy

from ..base import BaseConnector, ConnectorExecutionError

# Import individual notifier modules
from . import github_pr
from . import slack
from . import ms_teams
from . import ms_sentinel
from . import sumologic
from . import json_notifier
from . import console
from . import jira
from . import webhook

# Import shared formatters
from ...formatters import get_all_formatters

logger = logging.getLogger(__name__)


class SocketTier1Scanner(BaseConnector):
    """Runs the Socket CLI reachability analysis and returns the generated .socket.facts.json

    Behavior:
    - Respects SOCKET_TIER_1_ENABLED env var (and CLI param via connector config)
    - Requires SOCKET_ORG and SOCKET_SECURITY_API_KEY or SOCKET_SECURITY_API_TOKEN
    - Supports additional params via SOCKET_ADDITIONAL_PARAMS environment variable
    - Runs `socket scan reach --org <org> <target>` in an isolated temp CWD
    - Reads the generated .socket.facts.json and returns parsed JSON
    """

    FACTS_FILENAME = ".socket.facts.json"

    def is_enabled(self) -> bool:
        # Check config object first (which already handles environment variables)
        # connectors.yaml defines the parameter as 'socket_tier_1_enabled'
        try:
            if hasattr(self.config, 'get'):
                cfg_val = self.config.get('socket_tier_1_enabled', None)
            else:
                cfg_val = getattr(self.config, 'socket_tier_1_enabled', None)
            if isinstance(cfg_val, bool):
                return cfg_val
            if cfg_val:
                return True
        except Exception:
            pass
        return False

    def _get_auth_env(self) -> Dict[str, str]:
        env = {}
        # Use Config object exclusively - it already handles environment variables
        # and Socket API auto-discovery with proper precedence
        
        # Get organization from config (which already handles SOCKET_ORG, SOCKET_ORG_SLUG, etc.)
        org = (
            self.config.get('socket_org') if hasattr(self.config, 'get') 
            else getattr(self.config, 'socket_org', None)
        )
        
        # Get API key from config (which already handles SOCKET_SECURITY_API_KEY, SOCKET_SECURITY_API_TOKEN, etc.)
        api_key = (
            self.config.get('socket_api_key') if hasattr(self.config, 'get') 
            else getattr(self.config, 'socket_api_key', None)
        )
        logger.debug(f" Socket Tier1 auth - org: '{org}', api_key_set: {bool(api_key)}")
        
        if org:
            env['SOCKET_ORG'] = org
        if api_key:
            env['SOCKET_SECURITY_API_KEY'] = api_key
        return env

    def _parse_additional_params(self) -> List[str]:
        # Use config object exclusively - it already handles SOCKET_ADDITIONAL_PARAMS env var
        raw = (
            self.config.get('socket_additional_params') if hasattr(self.config, 'get') 
            else getattr(self.config, 'socket_additional_params', '')
        )
        if not raw:
            return []
        # Allow comma-separated or regular shell splitting
        if ',' in raw:
            parts = [p.strip() for p in raw.split(',') if p.strip()]
            # further split any parts that contain spaces
            out: List[str] = []
            for p in parts:
                out.extend(shlex.split(p))
            return out
        return shlex.split(raw)

    def scan(self) -> Dict[str, Any]:
        # Verify auth
        auth_env = self._get_auth_env()
        if not auth_env.get('SOCKET_ORG') or not auth_env.get('SOCKET_SECURITY_API_KEY'):
            raise ConnectorExecutionError('Socket Tier 1 scanner requires SOCKET_ORG and SOCKET_SECURITY_API_KEY or SOCKET_SECURITY_API_TOKEN to be set')

        # Build command
        additional = self._parse_additional_params()
        # Default target is current dir
        target = '.'
        cmd = ['socket', 'scan', 'reach', '--org', auth_env['SOCKET_ORG'], '.']
        # Add additional options before the target if they look like flags
        # To be safe, append all additional params before target
        if additional:
            # remove target and rebuild: socket scan reach --org <org> [additional...] .
            cmd = ['socket', 'scan', 'reach', '--org', auth_env['SOCKET_ORG']] + additional + ['.']

        logger.info('Running Socket Tier1 reachability: %s', ' '.join(shlex.quote(p) for p in cmd))

        # Run in isolated temp dir to avoid clobbering current CWD .socket.facts.json
        tempdir = tempfile.mkdtemp(prefix='socket_tier1_')
        try:
            # Run the socket CLI from the configured workspace directory (target).
            # The CLI writes .socket.facts.json in the CWD, so executing it from the
            # workspace ensures the output lands in the expected project directory.
            try:
                cwd = str(self.config.workspace) if hasattr(self.config, 'workspace') else os.getcwd()
            except Exception:
                cwd = os.getcwd()
            proc_env = os.environ.copy()
            proc_env.update(auth_env)

            # Execute command
            completed = subprocess.run(cmd, cwd=cwd, env=proc_env, capture_output=True, text=True)
            logger.debug('Socket CLI stdout: %s', completed.stdout)
            logger.debug('Socket CLI stderr: %s', completed.stderr)

            if completed.returncode != 0:
                raise ConnectorExecutionError(f"Socket CLI failed (exit {completed.returncode}): {completed.stderr.strip()}")

            # Locate .socket.facts.json in cwd (or tempdir). Prefer cwd
            facts_path = Path(cwd) / self.FACTS_FILENAME
            if not facts_path.exists():
                # try tempdir
                facts_path = Path(tempdir) / self.FACTS_FILENAME

            # If facts file still doesn't exist, raise
            if not facts_path.exists():
                raise ConnectorExecutionError(f"Socket CLI did not produce {self.FACTS_FILENAME} in cwd {cwd}")

            # Read and parse facts file
            try:
                with facts_path.open('r', encoding='utf-8') as fh:
                    raw = json.load(fh)
            except Exception as e:
                raise ConnectorExecutionError(f"Failed to read/parse {facts_path}: {e}")

            # Convert raw socket facts to connector output shape expected by connector manager
            processed = self._convert_to_socket_facts(raw)

            # Return processed wrapper (manager will call BaseConnector._process_results when appropriate)
            return processed

        finally:
            # We intentionally do not remove tempdir immediately so callers may inspect; cleanup could be added later
            pass

    def _make_purl(self, comp: Dict[str, Any]) -> str:
        """Construct a best-effort purl from a component entry."""
        typ = comp.get('type')
        namespace = comp.get('namespace')
        name = comp.get('name') or comp.get('id')
        version = comp.get('version')
        if not name:
            return ''
        # Basic purl: pkg:type/namespace/name@version (percent-encode @ in namespace if needed)
        if namespace:
            # If namespace already contains @ (scoped npm), percent-encode
            ns = namespace.replace('@', '%40')
            p = f"pkg:{typ}/{ns}/{name}"
        else:
            p = f"pkg:{typ}/{name}"
        if version:
            p = p + f"@{version}"
        return p

    def _determine_reachability(self, vuln: Dict[str, Any], comp: Dict[str, Any]) -> Dict[str, Any]:
        """Determine the reachability state for a vulnerability on a component.

        Returns a mapping with keys:
          - type: one of reachable|unreachable|unknown|error
          - undeterminableReachability: True/False (if data indicates)
          - trace: list of trace strings
        """
        out: Dict[str, Any] = {"type": "unknown", "undeterminableReachability": False, "trace": []}
        rdata = vuln.get('reachabilityData') or {}
        if rdata.get('undeterminableReachability'):
            out['undeterminableReachability'] = True
            return out

        # Look into component reachability entries which map ghsa_id -> reachability list
        target_id = vuln.get('ghsaId') or vuln.get('cveId') or vuln.get('id')
        comp_reach = comp.get('reachability') or []
        matched = None
        for entry in comp_reach:
            if not target_id:
                continue
            entry_id = entry.get('ghsa_id')
            if entry_id and str(entry_id).lower() == str(target_id).lower():
                matched = entry
                break

        # Build patterns list from reachabilityData.pattern if present (but do not commit to out['trace'] yet)
        patterns = rdata.get('pattern') or []

        if matched:
            # examine matched reachability entries
            for r in matched.get('reachability', []):
                t = r.get('type')
                if t == 'reachable':
                    out['type'] = 'reachable'
                elif t == 'unreachable' and out['type'] != 'reachable':
                    out['type'] = 'unreachable'
                elif t == 'missing_support' and out['type'] not in ('reachable', 'unreachable'):
                    # missing_support means analysis couldn't determine reachability, treat as unknown
                    out['type'] = 'unknown'

                # For reachable entries, build a structured trace from 'matches'
                if t == 'reachable':
                    matches = r.get('matches') or []
                    # matches is expected to be nested lists: [[{package, sourceLocation, ...}, ...], ...]
                    for match_group in matches:
                        for m in match_group:
                            pkg = m.get('package') or m.get('packageName') or ''
                            src = m.get('sourceLocation') or {}
                            start = src.get('start') or {}
                            line = start.get('line')
                            col = start.get('column')
                            end = src.get('end') or {}
                            end_line = end.get('line')
                            end_col = end.get('column')
                            filename = src.get('filename')
                            # format like: 'owasp-nodejs-goat - server.js 72:12-75:6'
                            loc = ''
                            if filename:
                                if line is not None:
                                    if end_line is not None:
                                        loc = f"{filename} {line}:{col if col is not None else ''}-{end_line}:{end_col if end_col is not None else ''}"
                                    else:
                                        loc = f"{filename} {line}:{col if col is not None else ''}"
                                else:
                                    loc = f"{filename}"

                            entry_line = ''
                            if pkg:
                                # plain package name without bullets
                                entry_line = f"{pkg} - {loc}" if loc else f"{pkg}"
                            else:
                                entry_line = f"{loc}" if loc else ''
                            # Only add non-empty lines
                            if entry_line:
                                out['trace'].append(entry_line)
                    # append final line indicating the vulnerable component and version
                    comp_name = comp.get('name') or comp.get('id')
                    comp_ver = comp.get('version')
                    if comp_name:
                        if comp_ver:
                            out['trace'].append(f"  -> {comp_name}@{comp_ver}")
                        else:
                            out['trace'].append(f"  -> {comp_name}")

        # Do not include pattern lines in the trace output; only include
        # the formatted match lines and the final '-> component@version' line.

        # If not reachable, do not include patterns or reachability trace (per requirement)
        if out['type'] != 'reachable':
            out['trace'] = []

        # If no matched reachability entry was found, this vulnerability is not applicable to this component version
        if matched is None:
            out['type'] = 'not_applicable'
            return out
        
        # If patterns exist but no matched reachability and not undeterminable, leave as unknown
        return out

    def _format_match_groups(self, matches_or_details: Any) -> str:
        """Format match-groups or a details dict into a human-readable multi-line string.

        Accepts either:
          - a list of match groups (each group is a list of frames/dicts), or
          - a dict with keys like 'matches', 'trace', 'purl', 'patterns'

        Returns a multi-line string suitable for printing in notifier details.
        """
        lines: List[str] = []
        try:
            # If a dict was passed, prefer explicit fields
            if isinstance(matches_or_details, dict):
                det = matches_or_details
                # include patterns first if present
                pats = det.get('patterns') or det.get('pattern') or []
                for p in pats:
                    lines.append(str(p))

                # include trace lines if provided (already formatted)
                trace = det.get('trace') or []
                if isinstance(trace, str):
                    if trace:
                        lines.append(trace)
                elif isinstance(trace, list):
                    for t in trace:
                        lines.append(str(t))

                # include matches (raw) if present and no trace
                raw_matches = det.get('matches') or det.get('raw_matches') or None
                if raw_matches and isinstance(raw_matches, list):
                    # reuse legacy formatting from match-groups
                    for mg in raw_matches:
                        if not mg:
                            continue
                        # first frame
                        f0 = mg[0]
                        src0 = f0.get('sourceLocation') or {}
                        fname = src0.get('filename') or src0.get('file') or ''
                        start = src0.get('start') or {}
                        line = start.get('line')
                        col = start.get('column')
                        if fname:
                            entry = f"{fname}"
                            if line is not None:
                                entry += f" - {line}:{col if col is not None else ''}"
                            lines.append(entry)
                        # other frames
                        for frame in mg[1:]:
                            pkg = frame.get('package') or frame.get('module') or ''
                            src = frame.get('sourceLocation') or {}
                            fname = src.get('filename') or src.get('file') or ''
                            start = src.get('start') or {}
                            l = start.get('line')
                            c = start.get('column')
                            left = pkg or fname or ''
                            if not left:
                                continue
                            line = f"  -> {left}"
                            if l is not None:
                                line += f" {l}:{c if c is not None else ''}"
                            lines.append(line)

                # always include purl if present
                purl = det.get('purl')
                if purl:
                    lines.append(f"purl: {purl}")

                return "\n".join(lines).strip()

            # If a list of match groups was provided, format similarly
            if isinstance(matches_or_details, list):
                for mg in matches_or_details:
                    if not mg:
                        continue
                    # first frame
                    f0 = mg[0]
                    src0 = f0.get('sourceLocation') or {}
                    fname = src0.get('filename') or src0.get('file') or ''
                    start = src0.get('start') or {}
                    line = start.get('line')
                    col = start.get('column')
                    if fname:
                        entry = f"{fname}"
                        if line is not None:
                            entry += f" - {line}:{col if col is not None else ''}"
                        lines.append(entry)
                    # other frames
                    for frame in mg[1:]:
                        pkg = frame.get('package') or frame.get('module') or ''
                        src = frame.get('sourceLocation') or {}
                        fname = src.get('filename') or src.get('file') or ''
                        start = src.get('start') or {}
                        l = start.get('line')
                        c = start.get('column')
                        left = pkg or fname or ''
                        if not left:
                            continue
                        line = f"  -> {left}"
                        if l is not None:
                            line += f" {l}:{c if c is not None else ''}"
                        lines.append(line)
                return "\n".join(lines).strip()
        except Exception:
            logger.debug('Failed to format match groups/details', exc_info=True)
        # fallback to string coercion
        try:
            return str(matches_or_details)
        except Exception:
            return ''



    def _convert_to_socket_facts(self, raw_results: Any) -> Dict[str, Any]:
        """Convert Socket CLI .socket.facts.json into a Socket facts wrapper with notifications

        - Keeps components list as-is (NO MODIFICATIONS to components from .socket.facts.json)
        - For each vulnerability in a component, generates alerts for notifications only
        - Returns original components unchanged and puts processed notifications in notifications section
        """
        # Return original components unchanged - no modifications allowed per requirement
        original_components = raw_results.get('components', []) if isinstance(raw_results, dict) else []
        
        if not original_components:
            # No socket components found, return empty structure
            return {"components": [], "notifications": {}}

        # Generate alerts for notifications only - do NOT modify original components
        components_with_alerts_for_notifications = []
        
        for c in original_components:
            alerts: List[Dict[str, Any]] = []
            vulns = c.get('vulnerabilities') or []
            
            for v in vulns:
                vid = v.get('ghsaId') or v.get('cveId') or v.get('id') or v.get('vulnId')
                # severity heuristics (pull from multiple possible fields)
                sev_val = None
                # direct textual severity
                if v.get('severity'):
                    sev_val = v.get('severity')
                # numeric cvss or score
                elif v.get('cvss'):
                    sev_val = v.get('cvss')
                elif v.get('cvssScore'):
                    sev_val = v.get('cvssScore')
                elif v.get('cvss_v3'):
                    sev_val = v.get('cvss_v3')
                elif v.get('cvssv3'):
                    sev_val = v.get('cvssv3')

                sev = 'unknown'
                try:
                    if isinstance(sev_val, (int, float)) or (isinstance(sev_val, str) and str(sev_val).replace('.', '', 1).isdigit()):
                        s = float(sev_val)
                        if s >= 9.0:
                            sev = 'critical'
                        elif s >= 7.0:
                            sev = 'high'
                        elif s >= 4.0:
                            sev = 'medium'
                        else:
                            sev = 'low'
                    elif sev_val:
                        # non-numeric textual severity
                        sev = str(sev_val).lower()
                except Exception:
                    sev = 'unknown'

                reach = self._determine_reachability(v, c)
                
                # Skip vulnerabilities that are not applicable to this component version
                if reach.get('type') == 'not_applicable':
                    continue

                purl = self._make_purl(c)

                trace_str = '\n'.join(reach.get('trace') or [])

                # Map reachability state to severity per user requirements
                reach_type = (reach.get('type') or '')
                final_sev = sev
                if reach_type == 'reachable':
                    final_sev = 'critical'
                elif reach_type in ('unknown', 'error') or reach.get('undeterminableReachability'):
                    final_sev = 'high'
                elif reach_type == 'unreachable':
                    final_sev = 'low'

                alert: Dict[str, Any] = {
                    'title': vid or v.get('title') or v.get('description') or 'vulnerability',
                    'severity': final_sev,
                    'type': 'vulnerability',
                    'category': 'vulnerability',
                    'subType': 'socket-tier1',
                    'generatedBy': 'socket-tier1',
                    'props': {
                        'cveId': v.get('cveId'),
                        'ghsaId': v.get('ghsaId'),
                        'range': v.get('range'),
                        'purl': purl,
                        'reachability': reach.get('type'),
                        'undeterminableReachability': reach.get('undeterminableReachability'),
                        'trace': trace_str,
                        'severity': final_sev,
                    }
                }
                alerts.append(alert)

            # Create a copy of the component with alerts for notifications only
            # This is only used for generating notifications, NOT returned in components
            if alerts:
                comp_with_alerts = deepcopy(c)
                comp_with_alerts['alerts'] = alerts
                components_with_alerts_for_notifications.append(comp_with_alerts)

        # Build notifications for each notifier type using components with alerts
        notifications_by_notifier = {}
        try:
            if components_with_alerts_for_notifications:
                notifications_by_notifier = self.generate_notifications(components_with_alerts_for_notifications)
        except Exception:
            # best-effort: do not fail conversion if notifications building errors
            logger.exception('Failed to build notifications for socket_tier1')

        # Return ORIGINAL components unchanged and notifications separately
        return {
            'components': original_components,  # Original components with NO modifications
            'notifications': notifications_by_notifier
        }



    def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
        """Produce consolidated notification rows compatible with the central notifier.

        Return canonical rows in the shape used by other connectors and the
        `normalize_components` helper: [file/component, severity, message/title, location/details].

        For Socket Tier1, since components are returned unchanged (without alerts),
        we need to reconstruct the alert information from the notifications.
        """
        rows: List[List[str]] = []
        
        # For Socket Tier1, alerts are not in components but in notifications
        # We need to build rows from the notification data
        notifications = processed_results.get('notifications', {})
        
        # Extract alert information from any notification format that has structured data
        # Priority: use console notifications if available as they're most direct
        console_notifications = notifications.get('console', [])
        if console_notifications:
            for notif in console_notifications:
                # Console notifications should have the alert data we need
                file_col = notif.get('component') or notif.get('file') or '-'
                sev = notif.get('severity') or ''
                title = notif.get('title') or notif.get('message') or ''
                loc = notif.get('location') or notif.get('details') or ''
                rows.append([str(file_col), str(sev), str(title), str(loc)])
        else:
            # Fallback: try to extract from any other notification format
            for notifier_type, notifier_data in notifications.items():
                if isinstance(notifier_data, list):
                    for notif in notifier_data:
                        if isinstance(notif, dict):
                            file_col = notif.get('component') or notif.get('file') or notif.get('purl') or '-'
                            sev = notif.get('severity') or ''
                            title = notif.get('title') or notif.get('message') or notif.get('vulnerability') or ''
                            loc = notif.get('location') or notif.get('details') or notif.get('trace') or ''
                            rows.append([str(file_col), str(sev), str(title), str(loc)])
                    break  # Only use first available notifier data to avoid duplicates
        
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
        
        # Filter components by severity before formatting
        filtered_components = []
        for component in components:
            filtered_alerts = []
            for alert in component.get('alerts', []):
                # Filter by severity - only include alerts that match allowed severities
                alert_severity = (alert.get('severity') or '').strip().lower()
                if alert_severity and hasattr(self, 'allowed_severities') and alert_severity not in self.allowed_severities:
                    continue  # Skip this alert - severity not enabled
                filtered_alerts.append(alert)
            
            # Only include component if it has filtered alerts
            if filtered_alerts:
                filtered_component = component.copy()
                filtered_component['alerts'] = filtered_alerts
                filtered_components.append(filtered_component)
        
        if not filtered_components:
            return {}
        
        # Build notifications for each notifier type using Socket Tier1-specific modules
        notifications_by_notifier = {}
        notifications_by_notifier['github_pr'] = github_pr.format_notifications(filtered_components)
        notifications_by_notifier['slack'] = slack.format_notifications(filtered_components)
        notifications_by_notifier['msteams'] = ms_teams.format_notifications(filtered_components)
        notifications_by_notifier['ms_sentinel'] = ms_sentinel.format_notifications(filtered_components)
        notifications_by_notifier['sumologic'] = sumologic.format_notifications(filtered_components)
        notifications_by_notifier['json'] = json_notifier.format_notifications(filtered_components)
        notifications_by_notifier['console'] = console.format_notifications(filtered_components)
        notifications_by_notifier['jira'] = jira.format_notifications(filtered_components)
        notifications_by_notifier['webhook'] = webhook.format_notifications(filtered_components)
        
        return notifications_by_notifier
