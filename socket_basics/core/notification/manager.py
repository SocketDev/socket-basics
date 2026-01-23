import importlib
import logging
import os
from typing import Any, Dict, List, Optional

from socket_basics.core.notification.base import BaseNotifier
from socket_basics.core.config import (
    load_connectors_config,
    get_slack_webhook_url,
    get_webhook_url,
    get_ms_sentinel_workspace_id,
    get_jira_url,
    get_sumologic_endpoint,
    get_github_token,
    get_jira_email,
    get_jira_api_token,
    get_socket_basics_severities,
    get_github_workspace
)

logger = logging.getLogger(__name__)


class NotificationManager:
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
                    slack_url = get_slack_webhook_url()
                    if (
                        slack_url
                        or (self.app_config and self.app_config.get('slack_webhook_url'))
                    ):
                        enabled = True
                        if slack_url:
                            enable_cause = 'env:SLACK_WEBHOOK_URL or INPUT_SLACK_WEBHOOK_URL'
                        else:
                            enable_cause = 'app_config:slack_webhook_url'

                # Webhook generic
                if name.lower() == 'webhook':
                    webhook = get_webhook_url()
                    if (
                        webhook
                        or (self.app_config and self.app_config.get('webhook_url'))
                    ):
                        enabled = True
                        if webhook:
                            enable_cause = 'env:WEBHOOK_URL or INPUT_WEBHOOK_URL'
                        else:
                            enable_cause = 'app_config:webhook_url'

                # MS Sentinel
                if name.lower() == 'ms_sentinel':
                    sentinel_id = get_ms_sentinel_workspace_id()
                    if (
                        sentinel_id
                        or (self.app_config and self.app_config.get('ms_sentinel_workspace_id'))
                    ):
                        enabled = True
                        if sentinel_id:
                            enable_cause = 'env:MS_SENTINEL_WORKSPACE_ID or INPUT_MS_SENTINEL_WORKSPACE_ID'
                        else:
                            enable_cause = 'app_config:ms_sentinel_workspace_id'

                # Jira
                if name.lower() == 'jira':
                    jira = get_jira_url()
                    if (
                        jira
                        or (self.app_config and self.app_config.get('jira_url'))
                    ):
                        enabled = True
                        if jira:
                            enable_cause = 'env:JIRA_URL or INPUT_JIRA_URL'
                        else:
                            enable_cause = 'app_config:jira_url'

                # SumoLogic
                if name.lower() == 'sumologic':
                    sumologic = get_sumologic_endpoint()
                    if (
                        sumologic
                        or (self.app_config and self.app_config.get('sumologic_endpoint'))
                    ):
                        enabled = True
                        if sumologic:
                            enable_cause = 'env:SUMOLOGIC_ENDPOINT or INPUT_SUMOLOGIC_ENDPOINT'
                        else:
                            enable_cause = 'app_config:sumologic_endpoint'

                # Github PR notifier: token presence
                if name.lower() == 'github_pr':
                    github_token = get_github_token()
                    if (
                        github_token
                        or (self.app_config and self.app_config.get('github_token'))
                    ):
                        enabled = True
                        if github_token:
                            enable_cause = 'env:GITHUB_TOKEN or INPUT_GITHUB_TOKEN'
                            logger.info("GitHub PR notifier will be enabled - token detected")
                        else:
                            enable_cause = 'app_config:github_token'
                            logger.info("GitHub PR notifier will be enabled - token in config")
                    else:
                        logger.debug("GitHub PR notifier will NOT be enabled - no GITHUB_TOKEN found")
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
                        enable_cause = 'app_config:console_tabular_enabled or output_console_enabled'
                    if name.lower() == 'json' and (
                        self.app_config.get('console_json_enabled') or self.app_config.get('output_json_enabled')
                    ):
                        enabled = True
                except Exception as e:
                    logger.debug(f" Exception in console notifier check: {e}")
            except Exception as e:
                logger.debug(f" Exception in notifier enablement check: {e}")

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

                        # Resolve value priority: app_config (highest) -> env var -> default (lowest)
                        val = p_default

                        # Check env var (overrides default)
                        if env_var:
                            ev = os.getenv(env_var)
                            if ev is not None:
                                if p_type == 'bool':
                                    val = ev.lower() == 'true'
                                elif p_type == 'int':
                                    try:
                                        val = int(ev)
                                    except Exception:
                                        logger.warning("Failed to convert notifier param %s=%s to int for notifier %s; using default %s", pname, ev, name, p_default)
                                else:
                                    val = ev

                        # Check app_config (highest priority, overrides env var)
                        if self.app_config and pname in self.app_config:
                            app_val = self.app_config.get(pname)
                            if app_val is not None:
                                val = app_val

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
                    jira_email = get_jira_email() or (self.app_config and self.app_config.get('jira_email'))
                    jira_token = get_jira_api_token() or (self.app_config and self.app_config.get('jira_api_token'))
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
        # Add repository, branch, and commit info from main config to facts
        # so notifiers can access this information for title formatting
        if self.app_config:
            facts['repository'] = self.app_config.get('repo', 'Unknown')  # Note: uses 'repo' not 'repository'
            facts['branch'] = self.app_config.get('branch', 'Unknown') 
            facts['commit_hash'] = self.app_config.get('commit_hash', 'Unknown')
            # Add full scan URL if available (from app_config or already in facts)
            if 'full_scan_html_url' not in facts:
                full_scan_url = self.app_config.get('full_scan_html_url')
                if full_scan_url:
                    facts['full_scan_html_url'] = full_scan_url
            
        # Determine allowed severities for notifications. Honor SOCKET_BASICS_SEVERITIES
        # environment variable (comma-separated), fall back to INPUT_FINDING_SEVERITIES,
        # and default to critical,high when not provided.
        try:
            sev_env = get_socket_basics_severities()
            if not sev_env:
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
                workspace = (self.app_config or {}).get('workspace') or get_github_workspace()
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
                    pname = p.get('name')
                    pgroup = p.get('group')
                    if pname and pgroup:
                        param_to_group[pname] = pgroup

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


        # Handle simplified per-notifier format from connectors
        # Connectors now provide notifications in simplified format:
        # {'notifier_key': [{'title': '...', 'content': 'formatted_content'}, ...]}
        # Severity filtering should be done in the connectors, not here
        per_notifier_notifications = {}
        if facts.get('notifications'):
            try:
                logger.debug('Processing connector-provided per-notifier notifications')
                raw_notifs = facts.get('notifications') or {}

                # Check if this is the new per-notifier format
                # (keys like 'github_pr', 'slack', 'console' vs old semantic groups)
                known_notifier_keys = {
                    'github_pr', 'slack', 'msteams', 'ms_sentinel', 'sumologic', 
                    'json', 'console', 'jira', 'webhook'
                }
                
                has_notifier_keys = any(key in known_notifier_keys for key in raw_notifs.keys()) if isinstance(raw_notifs, dict) else False
                
                if has_notifier_keys:
                    # New simplified format: connectors provide pre-formatted content
                    # No filtering needed - connectors handle severity filtering
                    for notifier_key, payload in raw_notifs.items():
                        if notifier_key not in known_notifier_keys:
                            continue
                        
                        # Validate payload format: should be list of {title, content} dicts
                        if isinstance(payload, list):
                            valid_items = []
                            for item in payload:
                                if isinstance(item, dict) and 'title' in item and 'content' in item:
                                    valid_items.append(item)
                                else:
                                    logger.warning('Invalid notification item for %s: expected {title, content}, got %s', 
                                                 notifier_key, type(item))
                            
                            if valid_items:
                                per_notifier_notifications[notifier_key] = valid_items
                        else:
                            logger.warning('Invalid payload format for %s: expected list, got %s', 
                                         notifier_key, type(payload))
                    
                    logger.debug('Processed %d notifier-specific notification formats', len(per_notifier_notifications))
                else:
                    # No new format notifications found
                    logger.debug('No per-notifier notification formats found')
                    
            except Exception:
                logger.exception('Failed to process connector-provided notifications')

            # Don't return early - continue to per-notifier filtering logic below

        # All connectors now use the new simplified per-notifier format, no legacy processing needed

        # Call notifiers with their specific pre-formatted data
        for n in self.notifiers:
            try:
                # Create a copy of facts for this notifier
                notifier_facts = facts.copy()
                
                # Map notifier class names to their expected notification keys
                notifier_name = getattr(n, "name", n.__class__.__name__.lower())
                notifier_key_map = {
                    'console': 'console',
                    'consolenotifier': 'console',
                    'slack': 'slack', 
                    'slacknotifier': 'slack',
                    'github_pr': 'github_pr',
                    'githubprnotifier': 'github_pr',
                    'jira': 'jira',
                    'jiranotifier': 'jira',
                    'msteams': 'msteams',
                    'msteamsnotifier': 'msteams',
                    'ms_teams': 'msteams',
                    'msteamsnotifier': 'msteams',
                    'ms_sentinel': 'ms_sentinel',
                    'mssentinelnotifier': 'ms_sentinel', 
                    'sumologic': 'sumologic',
                    'sumologicnotifier': 'sumologic',
                    'json': 'json',
                    'jsonnotifier': 'json',
                    'webhook': 'webhook',
                    'webhooknotifier': 'webhook'
                }
                
                # Get the appropriate notification key for this notifier
                notification_key = notifier_key_map.get(notifier_name.lower(), notifier_name.lower())
                
                # Debug logging
                if per_notifier_notifications:
                    logger.debug('Notifier %s -> notification_key %s, per_notifier_notifications keys: %s', 
                               notifier_name, notification_key, list(per_notifier_notifications.keys()))
                else:
                    logger.debug('Notifier %s -> notification_key %s, per_notifier_notifications is empty/None', 
                               notifier_name, notification_key)
                
                # If we have pre-formatted data for this notifier, use it
                if per_notifier_notifications and notification_key in per_notifier_notifications:
                    # Pass the per-notifier data in the simplified format: [{'title': '...', 'content': '...'}, ...]
                    notifier_data = per_notifier_notifications[notification_key]
                    notifier_facts['notifications'] = notifier_data
                    logger.debug('Using pre-formatted data for notifier %s: %s items', notifier_name, len(notifier_data) if isinstance(notifier_data, list) else 1)
                else:
                    # No pre-formatted data available - skip this notifier to avoid sending wrong format
                    logger.debug('No pre-formatted data found for notifier %s (key: %s), skipping to avoid format mismatch', notifier_name, notification_key)
                    continue
                
                n.notify(notifier_facts)
            except Exception:
                logger.exception("Notifier %s failed", getattr(n, "name", n.__class__.__name__))
