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
        # Allow explicit enable via env var
        val = os.environ.get('SOCKET_TIER_1_ENABLED', '').lower()
        if val in ('1', 'true', 'yes', 'on'):
            return True
        # Also allow enabling via config object if present
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
        # Prefer explicit environment variables, then fall back to values populated
        # into the Config object by CLI parsing (create_config_from_args)
        org = os.environ.get('SOCKET_ORG') or (self.config.get('socket_org') if hasattr(self.config, 'get') else getattr(self.config, 'socket_org', ''))
        api_key = (
            os.environ.get('SOCKET_SECURITY_API_KEY')
            or os.environ.get('SOCKET_SECURITY_API_TOKEN')
            or (self.config.get('socket_api_key') if hasattr(self.config, 'get') else getattr(self.config, 'socket_api_key', ''))
            or (self.config.get('socket_api_token') if hasattr(self.config, 'get') else getattr(self.config, 'socket_api_token', ''))
        )
        if org:
            env['SOCKET_ORG'] = org
        if api_key:
            env['SOCKET_SECURITY_API_KEY'] = api_key
        return env

    def _parse_additional_params(self) -> List[str]:
        raw = os.environ.get('SOCKET_ADDITIONAL_PARAMS', '')
        raw = raw or (self.config.get('socket_additional_params') if hasattr(self.config, 'get') else getattr(self.config, 'socket_additional_params', ''))
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
            if entry.get('ghsa_id') and str(entry.get('ghsa_id')).lower() == str(target_id).lower():
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
        """Convert Socket CLI .socket.facts.json into a Socket facts wrapper with alerts

        - Keeps components list as-is (adds 'alerts' list per component)
        - For each vulnerability in a component, emits an alert with CVE/GHSA, severity, reachability, purl, and trace
        """
        out: Dict[str, Any] = {"components": raw_results.get('components', [])}
        comps = raw_results.get('components') if isinstance(raw_results, dict) else None
        if not comps:
            # unknown shape, return raw
            return raw_results

        # Keep a map of generated alerts per component key so we can build
        # notifications without injecting those alerts back into the component
        generated_alerts_map: Dict[str, List[Dict[str, Any]]] = {}

        for c in comps:
            comp = deepcopy(c)
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

            orig_had_alerts = bool(c.get('alerts'))
            if orig_had_alerts:
                # preserve original alerts as provided by the Socket CLI
                try:
                    comp['alerts'] = deepcopy(c.get('alerts') or [])
                except Exception:
                    comp['alerts'] = c.get('alerts') or []
            else:
                # Ensure we do not leave an empty 'alerts' list on components
                if 'alerts' in comp:
                    try:
                        del comp['alerts']
                    except Exception:
                        comp.pop('alerts', None)

            # Store generated alerts in a separate map keyed by component name/id
            try:
                comp_key = comp.get('name') or comp.get('id') or '-'
                generated_alerts_map[comp_key] = alerts
            except Exception:
                # ignore mapping errors
                pass


        # Build notifications mapping so the notification manager uses our exact columns
        try:
            # Build 5-column rows with explicit headers
            rows_5col: List[List[str]] = []
            comps = out.get('components') or []
            for comp in comps:
                    comp_name = comp.get('name') or comp.get('id') or '-'
                    purl = self._make_purl(comp) or comp_name
                    # Include any alerts that already exist on the component
                    for a in comp.get('alerts', []):
                        props = a.get('props', {}) or {}
                        # first column: CVE/GHSA id or alert title
                        id_col = props.get('ghsaId') or props.get('cveId') or a.get('title') or ''
                        sev = a.get('severity') or props.get('severity') or ''
                        reach = str(props.get('reachability') or '').lower()
                        # trace: only include for reachable
                        trace_raw = props.get('trace') or ''
                        trace_str = ''
                        if isinstance(trace_raw, list):
                            trace_str = '\n'.join(str(x) for x in trace_raw)
                        elif isinstance(trace_raw, str):
                            trace_str = trace_raw

                        if reach != 'reachable':
                            # per requirement: only reachable items have traces
                            trace_str = ''

                        rows_5col.append([
                            str(id_col),
                            str(sev),
                            str(reach),
                            str(purl),
                            str(trace_str),
                        ])

                    # If component did not have original alerts, include generated ones
                    comp_key = comp.get('name') or comp.get('id') or '-'
                    gen_alerts = generated_alerts_map.get(comp_key, [])
                    if gen_alerts and not comp.get('alerts'):
                        for a in gen_alerts:
                            props = a.get('props', {}) or {}
                            id_col = props.get('ghsaId') or props.get('cveId') or a.get('title') or ''
                            sev = a.get('severity') or props.get('severity') or ''
                            reach = str(props.get('reachability') or '').lower()
                            trace_raw = props.get('trace') or ''
                            trace_str = ''
                            if isinstance(trace_raw, list):
                                trace_str = '\n'.join(str(x) for x in trace_raw)
                            elif isinstance(trace_raw, str):
                                trace_str = trace_raw
                            if reach != 'reachable':
                                trace_str = ''
                            purl = props.get('purl') or self._make_purl(comp) or comp_key
                            rows_5col.append([
                                str(id_col),
                                str(sev),
                                str(reach),
                                str(purl),
                                str(trace_str),
                            ])

            if rows_5col:
                # Attach connector-provided notifications with explicit headers
                # Include a generatedBy column so attribution travels with each row
                headers = ['CVE/GHSA', 'severity', 'reachability', 'purl', 'trace', 'generatedBy']
                out['notifications'] = [
                    {
                        'title': 'Socket Tier 1 Reachability',
                        'headers': headers,
                        'rows': [r + ['socket-tier1'] for r in rows_5col],
                    }
                ]
        except Exception:
            # best-effort: do not fail conversion if notifications building errors
            logger.exception('Failed to build notifications for socket_tier1')

        return {'components': out.get('components', []), 'notifications': out.get('notifications', [])}

    # Note: consolidated `notification_rows` implementation follows below.
    def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
        """Produce consolidated notification rows compatible with the central notifier.

        Return canonical rows in the shape used by other connectors and the
        `normalize_components` helper: [file/component, severity, message/title, location/details].

        This method accepts either the processed wrapper (with 'components') or
        the full `facts` dict that contains a `socket_tier1` key.
        """
        rows: List[List[str]] = []
        # Resolve components from multiple possible shapes
        comps = []
        if isinstance(processed_results, dict):
            if 'components' in processed_results and isinstance(processed_results.get('components'), list):
                comps = processed_results.get('components', [])
            elif 'socket_tier1' in processed_results and isinstance(processed_results['socket_tier1'], dict):
                comps = processed_results['socket_tier1'].get('components', [])
            elif 'socket_tier1' in processed_results and isinstance(processed_results['socket_tier1'], list):
                comps = processed_results['socket_tier1']
            else:
                comps = processed_results.get('components', [])

        for comp in comps:
            comp_name = comp.get('name') or comp.get('id') or '-'
            for a in comp.get('alerts', []):
                props = a.get('props', {}) or {}
                # File/component column: prefer purl, fall back to component name
                purl = props.get('purl') or ''
                file_col = purl or comp_name

                # Severity
                sev = a.get('severity') or props.get('severity') or ''

                # Message/title: use GHSA/CVE id if present, else alert title
                title = props.get('ghsaId') or props.get('cveId') or a.get('title') or a.get('message') or ''

                # Location/details: for reachable include formatted trace (multi-line), otherwise include purl or component
                trace_raw = props.get('trace') or ''
                trace_str = ''
                if isinstance(trace_raw, list):
                    trace_str = '\n'.join(str(x) for x in trace_raw)
                elif isinstance(trace_raw, str):
                    trace_str = trace_raw

                if str(props.get('reachability') or '').lower() == 'reachable':
                    # prepend patterns if present for context
                    patterns = props.get('reachabilityPatterns') or props.get('patterns') or []
                    pat_str = '\n'.join(str(p) for p in patterns) if patterns else ''
                    loc = ''
                    if pat_str:
                        loc = pat_str + ('\n' + trace_str if trace_str else '')
                    else:
                        loc = trace_str or purl or comp_name
                else:
                    # non-reachable: location should be purl (or component name) and no trace
                    loc = purl or comp_name

                rows.append([str(file_col), str(sev), str(title), str(loc)])
        return rows
