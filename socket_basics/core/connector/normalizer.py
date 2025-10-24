#!/usr/bin/env python3
"""
Normalization helpers for connector outputs.

This module exposes `normalize_components` which accepts connector output in
several common shapes (mapping of id->component, list of components, or a
socket-facts-like dict with 'components') and returns a dict with a
`components` list suitable for consolidation and a `notifications` list of rows
for notifiers. It intentionally does not live in manager.py or socket_basics.py.
"""
from typing import Any, Dict, List, Tuple
import logging
import os

logger = logging.getLogger(__name__)


def _to_component_list(obj: Any) -> List[Dict[str, Any]]:
    # Strict policy: accept only a list or a dict with 'components' list
    if not obj:
        return []
    if isinstance(obj, dict):
        if 'components' in obj and isinstance(obj['components'], list):
            return obj['components']
        # Any other dict shape is considered non-canonical under the new
        # policy; connectors must emit {'components': [...]}
        return []
    if isinstance(obj, list):
        return obj
    return []


def _normalize_alert(a: Dict[str, Any], connector: Any | None = None, default_generated_by: str | None = None) -> Dict[str, Any]:
    # Ensure required keys exist and are normalized
    a = dict(a)  # shallow copy
    # canonicalize severity
    if 'severity' in a and isinstance(a['severity'], str):
        a['severity'] = a['severity'].lower()
    # Minimal normalization: lowercase severity and ensure action exists

    # Check if this alert's rule is in the disabled rules list for any language
    # If so, set action to 'ignore' regardless of severity
    try:
        if connector and hasattr(connector, 'config'):
            rule_id = a.get('title') or a.get('ruleId') or a.get('props', {}).get('ruleId')
            if rule_id:
                # Check all language disabled_rules configs
                disabled_rule_params = [
                    'python_disabled_rules', 'javascript_disabled_rules', 'go_disabled_rules',
                    'java_disabled_rules', 'kotlin_disabled_rules', 'scala_disabled_rules',
                    'php_disabled_rules', 'ruby_disabled_rules', 'csharp_disabled_rules',
                    'dotnet_disabled_rules', 'c_disabled_rules', 'cpp_disabled_rules',
                    'swift_disabled_rules', 'rust_disabled_rules', 'elixir_disabled_rules',
                    'erlang_disabled_rules', 'trivy_disabled_rules'
                ]
                for param in disabled_rule_params:
                    try:
                        disabled_rules_str = connector.config.get(param, '')
                        if disabled_rules_str:
                            disabled_rules = [r.strip() for r in disabled_rules_str.split(',') if r.strip()]
                            if rule_id in disabled_rules:
                                logger.debug(f"Rule {rule_id} is disabled via {param}, setting action to 'ignore'")
                                a['action'] = 'ignore'
                                return a
                    except Exception:
                        pass
    except Exception:
        logger.debug('Failed to check disabled rules for alert', exc_info=True)

    # Ensure action is one of allowed values; derive from severity when missing/invalid
    try:
        allowed_actions = ('error', 'warn', 'monitor', 'ignore')
        act = (a.get('action') or '').strip().lower()
        if act not in allowed_actions:
            sev = (a.get('severity') or '').lower()
            # Prefer connector/config-level mapping when available
            try:
                cfg_mapped = None
                if connector and hasattr(connector, 'config') and hasattr(connector.config, 'get_action_for_severity'):
                    try:
                        cfg_mapped = connector.config.get_action_for_severity(sev or '')
                    except Exception:
                        cfg_mapped = None
                if cfg_mapped:
                    a['action'] = cfg_mapped
            except Exception:
                pass

            if not a.get('action'):
                # Mapping per requested policy:
                # critical -> error
                # high     -> warn
                # medium   -> monitor
                # low      -> ignore
                if sev == 'critical':
                    a['action'] = 'error'
                elif sev == 'high':
                    a['action'] = 'warn'
                elif sev == 'medium':
                    a['action'] = 'monitor'
                elif sev == 'low':
                    a['action'] = 'ignore'
                else:
                    a['action'] = 'monitor'
    except Exception:
        # If anything goes wrong, set a conservative default
        a['action'] = 'monitor'
    return a


def normalize_components(raw: Any, connector: Any | None = None) -> Tuple[Dict[str, Any], List[List[str]]]:
    """Normalize connector output into a socket-facts compatible components list.

    Returns a tuple (socket_facts_like_dict, notifications_rows).
    - socket_facts_like_dict: {'components': [ ... ]}
    - notifications_rows: list of rows (each row is a list of strings) derived
      from alerts that indicate action 'error' or 'warn' or any alert (connectors
      can filter as needed).
    """
    comps = _to_component_list(raw)
    normalized: List[Dict[str, Any]] = []
    notifications: List[List[str]] = []

    for comp in comps:
        try:
            c = dict(comp)
            # ensure id and type
            c.setdefault('id', c.get('name') or c.get('id') or '')
            c.setdefault('type', c.get('type') or 'generic')
            # ensure alerts list
            alerts = c.get('alerts') or []
            if not isinstance(alerts, list):
                alerts = [alerts]
            norm_alerts: List[Dict[str, Any]] = []
            for a in alerts:
                try:
                    na = _normalize_alert(a, connector=connector, default_generated_by=None)
                    # Helper: strip workspace prefix from any file paths so that
                    # outputs don't include local workspace parents like "../NodeGoat"
                    def _strip_workspace_prefix(path_val: Any) -> Any:
                        try:
                            if not path_val:
                                return path_val
                            pstr = str(path_val)
                            # If connector has config.workspace, try to use it
                            ws_root = None
                            ws_root = None
                            try:
                                if connector is not None and hasattr(connector, 'config'):
                                    ws_obj = getattr(connector.config, 'workspace', None)
                                    ws_root = getattr(ws_obj, 'path', None) or getattr(ws_obj, 'root', None) or ws_obj
                            except Exception:
                                ws_root = None
                            if ws_root:
                                try:
                                    if pstr.startswith(str(ws_root)):
                                        return os.path.normpath(os.path.relpath(pstr, str(ws_root)))
                                except Exception:
                                    pass
                                try:
                                    ws_name = os.path.basename(str(ws_root))
                                    parts = pstr.split(os.sep)
                                    if parts and (parts[0] == ws_name or (len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == ws_name)):
                                        if parts[0] == ws_name:
                                            parts = parts[1:]
                                        else:
                                            parts = parts[2:]
                                        candidate = os.path.normpath(os.path.join(*parts)) if parts else ''
                                        # If candidate still begins with workspace name (edgecases), strip it
                                        if candidate and candidate.startswith(ws_name + os.sep):
                                            candidate = candidate[len(ws_name) + 1:]
                                        return candidate
                                    # additionally, if original pstr still begins with workspace name, strip it
                                    if pstr.startswith(ws_name + os.sep):
                                        return os.path.normpath(pstr[len(ws_name) + 1:])
                                except Exception:
                                    pass
                            # Fallback: remove leading '../' or './' segments
                            while pstr.startswith('..' + os.sep) or pstr.startswith('.' + os.sep):
                                pstr = pstr.split(os.sep, 1)[1] if os.sep in pstr else ''
                            return pstr
                        except Exception:
                            return path_val
                    norm_alerts.append(na)
                    # build a default notification row for warn/error/critical
                    act = na.get('action') or ''
                    sev = na.get('severity') or ''
                    if act in ('error', 'warn') or sev in ('critical', 'high'):
                        # column order: component_id, severity, title, path:line
                        path = na.get('props', {}).get('filePath') or (na.get('location') or {}).get('path') or c.get('name') or c.get('id')
                        line = na.get('props', {}).get('startLine') or (na.get('location') or {}).get('line') or ''
                        # Strip workspace prefix from both props and location if present
                        try:
                            stripped = _strip_workspace_prefix(path)
                            # Write back into props/location too so downstream notifiers see cleaned paths
                            if 'props' in na and isinstance(na['props'], dict):
                                na['props']['filePath'] = stripped
                                if 'startLine' in na['props'] and na['props'].get('startLine'):
                                    na['props']['startLine'] = na['props'].get('startLine')
                            if 'location' in na and isinstance(na['location'], dict):
                                try:
                                    na['location']['path'] = stripped
                                except Exception:
                                    pass
                            path = stripped
                        except Exception:
                            pass
                        notifications.append([c.get('id') or c.get('name') or '', str(sev), na.get('title') or na.get('description') or '', f"{path}:{line}" if line else (path or '')])
                except Exception:
                    logger.exception('Failed to normalize alert for component %s', c.get('id'))
            c['alerts'] = norm_alerts
            normalized.append(c)
        except Exception:
            logger.exception('Failed to normalize component')

    return ({'components': normalized}, notifications)
