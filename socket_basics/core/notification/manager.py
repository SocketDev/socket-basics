import importlib
import logging
import os
from typing import Any, Dict, List, Optional

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import load_connectors_config

logger = logging.getLogger(__name__)


class NotificationManager:
    def notify_all(self, facts: Dict[str, Any]) -> None:
        # Debug: log facts at debug level (don't print raw structures unconditionally)
        try:
            logger.debug('notify_all facts: %s', {k: v for k, v in facts.items() if k != 'socket_tier1'})
            if 'socket_tier1' in facts:
                logger.debug('Raw socket_tier1 processed results: %s', facts.get('socket_tier1'))
        except Exception:
            logger.exception('Failed to debug-log notify_all facts')
        # ...existing code...
    """Loads notifier plugins based on a config dict.

    Config format:
    {
      "notifiers": {
         "console": {"module_path": "socket_basics.core.notification.console", "class": "ConsoleNotifier", "enabled": True}
      }
    }
    """

    def __init__(self, config: Dict[str, Any] | None = None, app_config: Optional[Dict[str, Any]] = None) -> None:
        """config: notifications.yaml dict; app_config: active application config (from Config._config)"""
        self.config = config or {}
        self.app_config = app_config or {}
        self.notifiers: List[BaseNotifier] = []

    def load_from_config(self) -> None:
        notifiers_cfg = self.config.get("notifiers", {})

        # Load connectors config to allow per-connector notification preferences
        connectors_cfg = {}
        try:
            connectors_cfg = load_connectors_config().get('connectors', {})
        except Exception:
            connectors_cfg = {}

        for name, cfg in notifiers_cfg.items():
            # By default use notifier enabled flag
            # Notifications.yaml no longer drives enable/disable directly; treat
            # entries as available plugins and decide enablement from CLI/env
            enabled = False
            enable_cause = None

            # Auto-enable Slack notifier when a webhook URL is present in the
            # environment or in the app_config. This allows users to enable
            # Slack by providing SLACK_WEBHOOK_URL in their environment (e.g. .env)
            # without editing notifications.yaml.
            # Check notifier-specific runtime parameters from environment or app_config
            try:
                # Slack: webhook
                if name.lower() == 'slack':
                    if (
                        os.getenv('SLACK_WEBHOOK_URL')
                        or os.getenv('INPUT_SLACK_WEBHOOK_URL')
                        or (self.app_config and self.app_config.get('slack_webhook_url'))
                    ):
                        enabled = True
                        if os.getenv('SLACK_WEBHOOK_URL'):
                            enable_cause = 'env:SLACK_WEBHOOK_URL'
                        elif os.getenv('INPUT_SLACK_WEBHOOK_URL'):
                            enable_cause = 'env:INPUT_SLACK_WEBHOOK_URL'
                        else:
                            enable_cause = 'app_config:slack_webhook_url'

                # Webhook generic
                if name.lower() == 'webhook':
                    if (
                        os.getenv('WEBHOOK_URL')
                        or os.getenv('INPUT_WEBHOOK_URL')
                        or (self.app_config and self.app_config.get('webhook_url'))
                    ):
                        enabled = True
                        if os.getenv('WEBHOOK_URL'):
                            enable_cause = 'env:WEBHOOK_URL'
                        elif os.getenv('INPUT_WEBHOOK_URL'):
                            enable_cause = 'env:INPUT_WEBHOOK_URL'
                        else:
                            enable_cause = 'app_config:webhook_url'

                # MS Sentinel
                if name.lower() == 'ms_sentinel':
                    if (
                        os.getenv('INPUT_MS_SENTINEL_WORKSPACE_ID')
                        or os.getenv('MS_SENTINEL_WORKSPACE_ID')
                        or (self.app_config and self.app_config.get('ms_sentinel_workspace_id'))
                    ):
                        enabled = True
                        if os.getenv('MS_SENTINEL_WORKSPACE_ID'):
                            enable_cause = 'env:MS_SENTINEL_WORKSPACE_ID'
                        elif os.getenv('INPUT_MS_SENTINEL_WORKSPACE_ID'):
                            enable_cause = 'env:INPUT_MS_SENTINEL_WORKSPACE_ID'
                        else:
                            enable_cause = 'app_config:ms_sentinel_workspace_id'

                # Jira
                if name.lower() == 'jira':
                    if (
                        os.getenv('INPUT_JIRA_URL')
                        or os.getenv('JIRA_URL')
                        or (self.app_config and self.app_config.get('jira_url'))
                    ):
                        enabled = True
                        if os.getenv('JIRA_URL'):
                            enable_cause = 'env:JIRA_URL'
                        elif os.getenv('INPUT_JIRA_URL'):
                            enable_cause = 'env:INPUT_JIRA_URL'
                        else:
                            enable_cause = 'app_config:jira_url'

                # SumoLogic
                if name.lower() == 'sumologic':
                    if (
                        os.getenv('INPUT_SUMOLOGIC_ENDPOINT')
                        or os.getenv('SUMOLOGIC_ENDPOINT')
                        or (self.app_config and self.app_config.get('sumologic_endpoint'))
                    ):
                        enabled = True
                        if os.getenv('SUMOLOGIC_ENDPOINT'):
                            enable_cause = 'env:SUMOLOGIC_ENDPOINT'
                        elif os.getenv('INPUT_SUMOLOGIC_ENDPOINT'):
                            enable_cause = 'env:INPUT_SUMOLOGIC_ENDPOINT'
                        else:
                            enable_cause = 'app_config:sumologic_endpoint'

                # Github PR notifier: token presence
                if name.lower() == 'github_pr':
                    if (
                        os.getenv('INPUT_GITHUB_TOKEN')
                        or os.getenv('GITHUB_TOKEN')
                        or (self.app_config and self.app_config.get('github_token'))
                    ):
                        enabled = True
                        if os.getenv('GITHUB_TOKEN'):
                            enable_cause = 'env:GITHUB_TOKEN'
                        elif os.getenv('INPUT_GITHUB_TOKEN'):
                            enable_cause = 'env:INPUT_GITHUB_TOKEN'
                        else:
                            enable_cause = 'app_config:github_token'
            except Exception:
                pass

            # If the global CLI flag requests console output, enable console notifier
            try:
                # Console notifier: tabular or JSON console outputs
                try:
                    if name.lower() == 'console' and (
                        self.app_config.get('console_tabular_enabled') or self.app_config.get('output_console_enabled')
                    ):
                        enabled = True
                    if name.lower() == 'json' and (
                        self.app_config.get('console_json_enabled') or self.app_config.get('output_json_enabled')
                    ):
                        enabled = True
                except Exception:
                    pass
            except Exception:
                pass

            # If any connector requested this notifier via its notification_method param, enable it
            for connector_name, connector_cfg in connectors_cfg.items():
                # check runtime app_config for a connector-level notification_method (e.g., 'notification_method')
                param_name = 'notification_method'
                # connectors may map parameter names differently; check env-params and direct defaults
                requested = self.app_config.get(param_name)
                # also check per-connector env-overrides in app_config using prefix pattern
                key = f"{connector_name}_notification_method"
                requested = requested or self.app_config.get(key) or connector_cfg.get('notification_method') or None
                if isinstance(requested, str) and requested.lower() == name.lower():
                    enabled = True
                    break

            # If still not enabled, skip loading. Only emit info-level messages
            # about disabled notifiers when verbose mode is enabled.
            if not enabled:
                if self.app_config.get('verbose'):
                    logger.info("Notifier %s is not enabled (no runtime params) and will be skipped", name)
                else:
                    logger.debug("Notifier %s is not enabled and will be skipped", name)
                continue

            module_path = cfg.get("module_path")
            class_name = cfg.get("class")
            # Normalize parameters: support older dict shape and new list-of-params shape
            raw_params = cfg.get("parameters", {})
            params = {}
            try:
                if isinstance(raw_params, dict):
                    params = raw_params
                elif isinstance(raw_params, list):
                    # Each entry is a param definition: name, env_variable, default, type
                    for p in raw_params:
                        if not isinstance(p, dict):
                            logger.warning("Malformed parameter entry for notifier %s: expected dict, got %s", name, type(p))
                            continue
                        pname = p.get('name')
                        if not pname:
                            logger.warning("Notifier %s has parameter entry without a 'name' field: %s", name, p)
                            continue
                        if not pname:
                            continue
                        p_default = p.get('default')
                        env_var = p.get('env_variable')
                        p_type = p.get('type', 'str')

                        # Resolve value: app_config -> env var -> default
                        val = None
                        if self.app_config and pname in self.app_config:
                            val = self.app_config.get(pname)
                        elif env_var and os.getenv(env_var) is not None:
                            ev = os.getenv(env_var)
                            if p_type == 'bool':
                                val = ev.lower() == 'true'
                            elif p_type == 'int':
                                try:
                                    val = int(ev)
                                except Exception:
                                    logger.warning("Failed to convert notifier param %s=%s to int for notifier %s; using default %s", pname, ev, name, p_default)
                                    val = p_default
                            else:
                                val = ev
                        else:
                            val = p_default

                        params[pname] = val
                else:
                    params = {}
            except Exception:
                params = {}

            if not module_path or not class_name:
                logger.warning("Notifier %s missing module_path or class in config", name)
                continue

            # Allow notifier-specific runtime enrichment. For Jira, attach auth
            # details into params if they exist in the environment or app_config
            try:
                if name.lower() == 'jira':
                    jira_email = os.getenv('INPUT_JIRA_EMAIL') or os.getenv('JIRA_EMAIL') or (self.app_config and self.app_config.get('jira_email'))
                    jira_token = os.getenv('INPUT_JIRA_API_TOKEN') or os.getenv('JIRA_API_TOKEN') or (self.app_config and self.app_config.get('jira_api_token'))
                    if jira_email or jira_token:
                        # ensure params contains auth dict expected by JiraNotifier
                        params['auth'] = {'email': jira_email, 'api_token': jira_token}

            except Exception:
                # best-effort enrichment; do not fail loading notifier on env lookup issues
                pass

            try:
                module = importlib.import_module(module_path)
                cls = getattr(module, class_name)
                instance = cls(params)
                # attach runtime app config so notifiers can consult global flags
                try:
                    setattr(instance, 'app_config', self.app_config)
                except Exception:
                    pass
                self.notifiers.append(instance)
                if enable_cause:
                    logger.info("Loaded notifier: %s (%s) - enabled via %s", name, module_path, enable_cause)
                else:
                    logger.info("Loaded notifier: %s (%s)", name, module_path)
            except Exception as e:
                logger.exception("Failed to load notifier %s: %s", name, e)

    def notify_all(self, facts: Dict[str, Any]) -> None:
        # Determine allowed severities for notifications. Honor SOCKET_BASICS_SEVERITIES
        # environment variable (comma-separated), fall back to INPUT_FINDING_SEVERITIES,
        # and default to critical,high when not provided.
        try:
            sev_env = os.getenv('SOCKET_BASICS_SEVERITIES') or os.getenv('INPUT_FINDING_SEVERITIES')
            if sev_env is None:
                allowed_severities = {'critical', 'high'}
            else:
                allowed_severities = {s.strip().lower() for s in str(sev_env).split(',') if s.strip()}
        except Exception:
            allowed_severities = {'critical', 'high'}

        # If socket_tier1 produced connector-style notifications with explicit headers,
        # prefer those verbatim; however do not short-circuit the pipeline here.
        # Manager must still attempt to filter/prune connector-provided notifications
        # (remove header-only groups) before forwarding to notifiers so notifiers
        # never receive empty tables. Any diagnostics are logged but processing
        # continues into the filtering logic below.
        try:
            provided = facts.get('notifications') or {}
            if provided:
                try:
                    logger.debug('Connector-provided notifications present; will attempt filtering/pruning before delivery')
                except Exception:
                    pass
        except Exception:
            logger.debug('Socket Tier1 presence check failed', exc_info=True)

        # Build grouped notifications based on connectors.yaml `group` parameter metadata.
        try:
            connectors_cfg = load_connectors_config().get('connectors', {})
        except Exception:
            connectors_cfg = {}

        # If repository not present in facts, prefer workspace name so notifiers
        # can display something meaningful when not running in GH actions.
        try:
            if not facts.get('repository'):
                workspace = (self.app_config or {}).get('workspace') or os.getenv('GITHUB_WORKSPACE')
                if workspace:
                    try:
                        from pathlib import Path

                        facts['repository'] = Path(workspace).name
                    except Exception:
                        facts['repository'] = str(workspace)
        except Exception:
            pass

        # Build a mapping of parameter name -> group label
        param_to_group: Dict[str, str] = {}
        for c_name, c_cfg in connectors_cfg.items():
            for p in c_cfg.get('parameters', []) or []:
                if isinstance(p, dict) and p.get('name') and p.get('group'):
                    param_to_group[p.get('name')] = p.get('group')

        # Helper: determine group for an alert using props/connector heuristics
        def _alert_group(alert: Dict[str, Any], comp: Dict[str, Any]) -> str:
            props = alert.get('props', {}) or {}
            # Socket Tier 1 reachability alerts should be grouped separately
            # so they are not reported as 'Ungrouped'. Detect by explicit
            # generatedBy flag, the reachability subtype, or presence of
            # reachability props produced by the tier1 converter.
            try:
                if str(alert.get('generatedBy') or '').lower() == 'socket_tier1':
                    return 'Socket Tier 1 Reachability'
                if (alert.get('subType') or '').lower() == 'reachability':
                    return 'Socket Tier 1 Reachability'
                if props.get('reachability') is not None:
                    return 'Socket Tier 1 Reachability'
            except Exception:
                pass
            # Trivy image vs dockerfile
            scan_type = props.get('scanType') or ''
            if scan_type == 'image':
                return 'Container Image Scanning'
            if scan_type in ('dockerfile', 'df'):  # heuristic
                return 'Dockerfile Scanning'

            tool = (props.get('tool') or '').lower()
            if tool in ('trufflehog', 'truffle', 'secrets', 'secret'):
                return 'Secret Scanning'
            if tool == 'trivy' and (props.get('dockerfile') or props.get('dockerImage')):
                # image vs dockerfile guess
                if props.get('dockerImage'):
                    return 'Container Image Scanning'
                return 'Dockerfile Scanning'

            # Language-based SAST grouping
            # Note: component qualifiers use 'type' for language (e.g. qualifiers.type == 'javascript')
            lang = (props.get('language') or (comp.get('qualifiers') or {}).get('type') or '').lower()
            if lang == 'python' or 'python' in (props.get('ruleId') or '').lower():
                return 'SAST Python'
            if lang in ('javascript', 'js', 'typescript') or 'js-' in (props.get('ruleId') or '').lower() or 'ts-' in (props.get('ruleId') or '').lower():
                return 'SAST Javascript'

            # Fallbacks
            if comp.get('qualifiers', {}).get('scanner') in ('sast', 'opengrep'):
                return 'SAST'
            if comp.get('qualifiers', {}).get('scanner') in ('secrets',):
                return 'Secret Scanning'

            return 'Ungrouped'


        # If connectors already attached `facts['notifications']`, try to filter them
        # by allowed severities where possible, but otherwise respect connector rows.
        # Support two shapes for connector-provided notifications:
        #  - {group_label: [row1, row2, ...]}
        #  - {group_label: {'headers': [...], 'rows': [[...], ...]}}
        if facts.get('notifications'):
            try:
                logger.debug('Facts already contains notifications; attempting to apply severity filtering')
            except Exception:
                pass

            try:
                raw_notifs = facts.get('notifications') or {}
                filtered: Dict[str, Any] = {}

                def _process_payload_and_filter(group_label: str, headers, rows):
                    new_rows = []
                    if not rows:
                        return None
                    for r in rows:
                        sev_found = None
                        try:
                            # If headers are present, require a Severity header to perform filtering
                            if headers:
                                found_sev_index = None
                                for i, h in enumerate(headers):
                                    try:
                                        if isinstance(h, str) and h.strip().lower() == 'severity':
                                            found_sev_index = i
                                            break
                                    except Exception:
                                        continue
                                if found_sev_index is None:
                                    # Connector provided headers but omitted Severity column.
                                    # Warn and conservatively include all rows for this group
                                    logger.warning("Connector-provided notifications for '%s' missing 'Severity' header; skipping severity filtering for this group", group_label)
                                    sev_found = None
                                else:
                                    if isinstance(r, (list, tuple)) and found_sev_index < len(r):
                                        sev_found = str(r[found_sev_index] or '').lower()

                            # Fallback heuristic: most tables put severity in idx 1
                            if not sev_found:
                                if isinstance(r, (list, tuple)):
                                    if len(r) > 1:
                                        sev_found = str(r[1] or '').lower()
                                    if not sev_found or sev_found == '':
                                        for cell in r:
                                            try:
                                                if isinstance(cell, str) and str(cell).strip().lower() in allowed_severities:
                                                    sev_found = str(cell).strip().lower()
                                                    break
                                            except Exception:
                                                continue
                        except Exception:
                            sev_found = None

                        # If we couldn't determine a severity, conservatively include the row
                        if not sev_found or sev_found in allowed_severities:
                            new_rows.append(r)

                    if new_rows:
                        return {'headers': headers, 'rows': new_rows}
                    return None

                # raw_notifs may be a mapping {group_label: payload} or a list of table-dicts
                if isinstance(raw_notifs, dict):
                    for group_label, payload in raw_notifs.items():
                        headers = None
                        rows = []
                        if isinstance(payload, dict) and 'rows' in payload:
                            headers = payload.get('headers') or []
                            rows = payload.get('rows') or []
                        elif isinstance(payload, list):
                            rows = payload
                        else:
                            # unknown payload shape: skip it
                            continue

                        processed = _process_payload_and_filter(group_label, headers, rows)
                        if processed:
                            filtered[group_label] = processed
                elif isinstance(raw_notifs, list):
                    for item in raw_notifs:
                        if not isinstance(item, dict):
                            continue
                        title = item.get('title') or 'results'
                        headers = item.get('headers')
                        rows = item.get('rows') or []
                        processed = _process_payload_and_filter(title, headers, rows)
                        if processed:
                            filtered[title] = processed
                else:
                    # unrecognized notifications shape; skip filtering
                    filtered = {}

                # Prune any groups that ended up with zero rows (defensive)
                for g in list(filtered.keys()):
                    payload = filtered.get(g)
                    try:
                        if not payload or not isinstance(payload, dict) or not (payload.get('rows') or []):
                            del filtered[g]
                    except Exception:
                        try:
                            del filtered[g]
                        except Exception:
                            pass

                # Attach filtered notifications back to facts for notifiers.
                facts['notifications'] = filtered
                if not filtered:
                    try:
                        logger.info('No notifications remain after severity filtering; skipping notifier delivery')
                    except Exception:
                        pass
                    return
            except Exception:
                logger.exception('Failed while attempting to filter connector-provided notifications by severity')

            # Attach to notifiers straight away
            for n in self.notifiers:
                try:
                    n.notify(facts)
                except Exception:
                    logger.exception("Notifier %s failed", getattr(n, "name", n.__class__.__name__))
            return

        # Special handling: always use connector notification_rows for Socket Tier 1
        # Connector may supply a dict with headers and rows; prefer that shape
        notifications: Dict[str, Any] = {}
        if 'socket_tier1' in facts:
            # If connectors attached a `notifications` mapping with headers+rows,
            # respect it verbatim (this allows connectors to control headings and
            # column counts). If not present, fall back to the scanner.notification_rows
            # legacy method (list-of-rows).
            provided = facts.get('notifications') or {}
            # Accept either the canonical top-level mapping or connector-attached mapping
            if isinstance(provided, dict) and provided.get('Socket Tier 1 Reachability'):
                # If the connector provides headers/rows, use them directly
                notifications = provided
            else:
                # Fall back to scanner.notification_rows when no connector-provided mapping exists
                from socket_basics.core.connector.socket_tier1.scanner import SocketTier1Scanner
                scanner = SocketTier1Scanner(config=None)
                rows = scanner.notification_rows(facts)
                try:
                    logger.debug('Rows returned by SocketTier1Scanner.notification_rows: %s', rows)
                except Exception:
                    logger.exception('Failed to debug-log socket_tier1 rows')

                # If rows are present, attach them under the standard group label
                if rows:
                    notifications['Socket Tier 1 Reachability'] = rows

            # Attach to facts and short-circuit the rest of the pipeline
            if notifications:
                try:
                    facts['notifications'] = notifications
                    logger.debug('Attached socket_tier1 notifications (authoritative): %s', notifications)
                except Exception:
                    logger.exception('Failed to attach socket_tier1 notifications')
                for n in self.notifiers:
                    try:
                        n.notify(facts)
                    except Exception:
                        logger.exception("Notifier %s failed", getattr(n, "name", n.__class__.__name__))
                return
        else:
            # Do not synthesize notification tables from component alerts here.
            # Connectors are authoritative for producing `facts['notifications']` in the
            # desired headers/rows shape. If no connector-provided notifications are
            # present, leave `facts` as-is so notifiers can decide how to render
            # `facts['components']` (this avoids manager guessing table shapes).
            logger.debug('No connector-provided notifications present; leaving facts.components intact for notifiers to render')

        # Attach notifications to facts so notifiers can render grouped tables.
        # If socket_tier1 attached authoritative rows above, skip canonicalization
        # to avoid mutating the connector-provided rows.
        try:
            if not facts.get('_socket_tier1_rows_attached'):
                # Canonicalize SAST rows so all notifiers receive a consistent
                # 4-column shape: [rule, file_path, lines, snippet]
                for g, rows in list(notifications.items()):
                    if g.lower().startswith('sast'):
                        new_rows = []
                        for r in rows:
                            try:
                                # Map common legacy shapes into [rule, file_path, lines, snippet]
                                rule = ''
                                full_path = ''
                                lines = ''
                                snippet = ''
                                if len(r) >= 5:
                                    first = (r[0] or '').lower() if isinstance(r[0], str) else ''
                                    if first in ('python', 'javascript', 'js', 'typescript', 'java', 'ruby', 'go', 'php', 'csharp', 'c', 'cpp', 'rust', 'kotlin', 'scala', 'swift'):
                                        # legacy: [language, rule, file, lines, snippet]
                                        rule = r[1]
                                        full_path = r[2]
                                        lines = r[3]
                                        snippet = r[4]
                                    else:
                                        # legacy: [rule, file_name, location, lines, snippet]
                                        rule = r[0]
                                        full_path = r[2] if len(r) > 2 else (r[1] if len(r) > 1 else '')
                                        lines = r[3]
                                        snippet = r[4]
                                elif len(r) == 4:
                                    # expected canonical shape: [rule, file_path, lines, snippet]
                                    rule, full_path, lines, snippet = r
                                elif len(r) == 3:
                                    # [rule, file, lines] -> no snippet
                                    rule, full_path, lines = r
                                    snippet = ''
                                else:
                                    rule = r[0] if len(r) > 0 else ''
                                    full_path = r[1] if len(r) > 1 else ''
                                    lines = r[2] if len(r) > 2 else ''
                                    snippet = r[3] if len(r) > 3 else ''

                                new_rows.append([rule, full_path, lines, snippet])
                            except Exception:
                                # If canonicalization fails, keep original row to avoid data loss
                                new_rows.append(r)
                        notifications[g] = new_rows

                if notifications:
                    facts['notifications'] = notifications
                else:
                    facts.setdefault('notifications', {})
            # Debug: log the notifications dict that will be passed to notifiers
            try:
                logger.debug('Grouped notifications to be passed to notifiers: %s', facts.get('notifications'))
            except Exception:
                logger.exception('Failed to debug-log notifications')
        except Exception:
            logger.exception('Failed to attach grouped notifications to facts')

        # Debug: dump notifications just before running notifiers to help
        # track down any remaining legacy-shaped rows (e.g. a leading "Language"
        # column). This writes a small JSON file to /tmp for inspection during
        # local runs.
        # Call notifiers
        # Debug: write a snapshot of grouped notifications to a temp file so
        # we can inspect the exact rows passed to notifiers when debugging

        for n in self.notifiers:
            try:
                n.notify(facts)
            except Exception:
                logger.exception("Notifier %s failed", getattr(n, "name", n.__class__.__name__))
