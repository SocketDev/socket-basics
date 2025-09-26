#!/usr/bin/env python3
"""
Connector Manager for Socket Security Basics
Handles dynamic loading and management of security scanning connectors
"""

import importlib
import logging
import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Type, Optional
from copy import deepcopy

from .base import BaseConnector, ConnectorError, ConnectorConfigError
from ..validator import SocketFactsValidator

logger = logging.getLogger(__name__)


class ConnectorManager:
    """Manages dynamic loading and execution of security scanning connectors"""
    
    def __init__(self, config, connectors_config_path: Optional[str] = None):
        """Initialize the connector manager
        
        Args:
            config: Main application configuration object
            connectors_config_path: Path to connectors.yaml config file
        """
        self.config = config
        self.connectors_config = self._load_connectors_config(connectors_config_path)
        self.loaded_connectors: Dict[str, BaseConnector] = {}
        # Determine allowed severities from environment or config; used by connectors
        try:
            sev_env = os.getenv('SOCKET_BASICS_SEVERITIES') or os.getenv('INPUT_FINDING_SEVERITIES')
            if sev_env is None:
                self.allowed_severities = {"critical", "high"}
            else:
                self.allowed_severities = {s.strip().lower() for s in str(sev_env).split(',') if s.strip()}
        except Exception:
            self.allowed_severities = {"critical", "high"}
        
    def _load_connectors_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load the connectors configuration from YAML file
        
        Args:
            config_path: Optional path to config file, defaults to connectors.yaml
            
        Returns:
            Dict containing connector configuration
        """
        if config_path is None:
            # Default to connectors.yaml in the socket_basics directory
            base_dir = Path(__file__).parent.parent.parent  # Go up from core/connector to socket_basics
            config_path = base_dir / "connectors.yaml"
        
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise ConnectorConfigError(f"Connectors config file not found: {config_path}")
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConnectorConfigError(f"Invalid YAML in connectors config: {e}")
    
    def get_enabled_connectors(self) -> List[str]:
        """Determine which connectors should be enabled
        
        Returns:
            List of connector names that should be loaded
        """
        # Check environment variable first
        env_var = self.connectors_config.get('settings', {}).get('enabled_connectors_env')
        if env_var and env_var in os.environ:
            enabled_str = os.environ[env_var].strip()
            
            if enabled_str.lower() == 'all':
                return list(self.connectors_config.get('connectors', {}).keys())
            elif enabled_str.lower() == 'none':
                return []
            else:
                return [name.strip() for name in enabled_str.split(',') if name.strip()]
        
        # Check config for explicit enablement
        enabled = []
        for name, connector_config in self.connectors_config.get('connectors', {}).items():
            if connector_config.get('enabled_by_default', False):
                enabled.append(name)
            else:
                # Allow per-connector enablement via environment variables declared in parameters
                for p in connector_config.get('parameters', []):
                    env_var = p.get('env_variable')
                    if env_var and env_var in os.environ:
                        val = os.environ.get(env_var, '').strip().lower()
                        if val in ('1', 'true', 'yes', 'on'):
                            enabled.append(name)
                            break
                    # Also allow enabling via parsed CLI/config attributes
                    param_name = p.get('name')
                    if param_name:
                        # Prefer Config.get(key) when available (Config object stores dynamic keys)
                        try:
                            if hasattr(self.config, 'get'):
                                cfg_val = self.config.get(param_name, None)
                            else:
                                cfg_val = getattr(self.config, param_name, None)

                            if isinstance(cfg_val, bool) and cfg_val:
                                enabled.append(name)
                                break
                            if cfg_val and not isinstance(cfg_val, bool):
                                enabled.append(name)
                                break
                        except Exception:
                            # ignore attribute access errors
                            pass
        
        # Fallback to default_enabled (can be a list or a mapping)
        if not enabled:
            default_enabled = self.connectors_config.get('settings', {}).get('default_enabled', [])
            if isinstance(default_enabled, dict):
                # mapping of connector name -> config; include keys where enabled_by_default is truthy
                for k, v in default_enabled.items():
                    try:
                        if isinstance(v, dict):
                            if v.get('enabled_by_default', False):
                                enabled.append(k)
                        else:
                            # if value is not a dict, assume presence means enabled
                            enabled.append(k)
                    except Exception:
                        continue
            elif isinstance(default_enabled, list):
                enabled = list(default_enabled)
            else:
                # unexpected shape, try to coerce to list
                try:
                    enabled = list(default_enabled)
                except Exception:
                    enabled = []

        # Special-case: avoid loading opengrep when no SAST languages are enabled
        try:
            if 'opengrep' in enabled:
                should_run = True
                if hasattr(self.config, 'should_run_sast') and callable(getattr(self.config, 'should_run_sast')):
                    should_run = bool(self.config.should_run_sast())
                else:
                    # Fallback: check for any opengrep rule files
                    try:
                        if hasattr(self.config, 'build_opengrep_rules') and callable(getattr(self.config, 'build_opengrep_rules')):
                            rules = self.config.build_opengrep_rules()
                            should_run = bool(rules)
                    except Exception:
                        should_run = True

                if not should_run:
                    logger.debug('No SAST languages enabled; removing opengrep from enabled connectors')
                    enabled = [e for e in enabled if e != 'opengrep']
        except Exception:
            # If anything goes wrong, keep the original enabled list
            pass

        return enabled
    
    def load_connector(self, connector_name: str) -> BaseConnector:
        """Dynamically load a connector by name
        
        Args:
            connector_name: Name of the connector to load
            
        Returns:
            Loaded connector instance
            
        Raises:
            ConnectorError: If connector cannot be loaded
        """
        if connector_name in self.loaded_connectors:
            return self.loaded_connectors[connector_name]
        
        connector_config = self.connectors_config.get('connectors', {}).get(connector_name)
        if not connector_config:
            raise ConnectorConfigError(f"No configuration found for connector: {connector_name}")
        
        try:
            # Import the connector module
            module_path = connector_config.get('module_path')
            if not module_path:
                # Fallback to standard path
                base_path = self.connectors_config.get('settings', {}).get('connector_base_path', 'core.connector')
                module_path = f"socket_basics.{base_path}.{connector_name}"
            
            module = importlib.import_module(module_path)
            
            # Get the connector class
            class_name = connector_config.get('class')
            if not class_name:
                raise ConnectorConfigError(f"No class name specified for connector: {connector_name}")
            
            connector_class = getattr(module, class_name)
            
            # Verify it's a BaseConnector subclass
            if not issubclass(connector_class, BaseConnector):
                raise ConnectorConfigError(
                    f"Connector class {class_name} must inherit from BaseConnector"
                )
            
            # Create instance
            connector_instance = connector_class(self.config)
            # Expose allowed severities to connectors so they can filter notifications
            try:
                setattr(connector_instance, 'allowed_severities', getattr(self, 'allowed_severities', {"critical", "high"}))
            except Exception:
                pass
            
            # Store for reuse
            self.loaded_connectors[connector_name] = connector_instance
            
            logger.info(f"Successfully loaded connector: {connector_name}")
            return connector_instance
            
        except ImportError as e:
            raise ConnectorError(f"Failed to import connector {connector_name}: {e}")
        except AttributeError as e:
            raise ConnectorError(f"Failed to find class {class_name} in connector {connector_name}: {e}")
        except Exception as e:
            raise ConnectorError(f"Failed to load connector {connector_name}: {e}")
    
    def load_all_enabled_connectors(self) -> Dict[str, BaseConnector]:
        """Load all enabled connectors
        
        Returns:
            Dict mapping connector names to loaded instances
        """
        enabled_names = self.get_enabled_connectors()
        connectors = {}
        
        for name in enabled_names:
            try:
                connector = self.load_connector(name)
                if connector.is_enabled():  # Additional check at connector level
                    connectors[name] = connector
                else:
                    logger.info(f"Connector {name} is loaded but disabled by configuration")
            except ConnectorError as e:
                logger.error(f"Failed to load connector {name}: {e}")
                
                # Check if we should fail fast
                if self.connectors_config.get('settings', {}).get('fail_fast', False):
                    raise
        
        return connectors
    
    def run_all_scans(self) -> Dict[str, Any]:
        """Run scans with all enabled connectors.

        Enforces the new connector contract: each connector.scan() must
        return a dict with keys:
          - 'components': list of component dicts
          - 'notifications': list of notification table dicts

        Returns:
            Dict with keys 'components' (list) and 'notifications' (list)
        """
        connectors = self.load_all_enabled_connectors()

        # aggregated components by id
        aggregated_components: Dict[str, Any] = {}
        # aggregated notifications keyed by title -> {'headers': ..., 'rows': [...]}
        notifications_by_title: Dict[str, Dict[str, Any]] = {}

        for name, connector in connectors.items():
            logger.info(f"Running scan with connector: {name}")
            try:
                results = connector.scan()
            except Exception as e:
                logger.error(f"Error running connector {name}: {e}")
                if self.connectors_config.get('settings', {}).get('fail_fast', False):
                    raise ConnectorError(f"Connector {name} failed: {e}")
                # skip this connector's results
                continue

            logger.debug("Connector %s returned raw results type=%s", name, type(results))

            # Basic logging for wrapper-like shapes
            try:
                if isinstance(results, dict):
                    for k, v in results.items():
                        if isinstance(v, dict) and isinstance(v.get('data'), list):
                            logger.debug("Connector %s raw wrapper '%s' contains %d inner items", name, k, len(v.get('data')))
            except Exception:
                logger.debug('Failed to log raw wrapper details for connector %s', name)

            # Enforce contract: connectors must return canonical dict
            if not isinstance(results, dict):
                logger.warning("Connector %s returned non-dict result; ignoring", name)
                continue

            # Validate incoming shape using strict validator. If the validator
            # package is not installed, skip validation but log a warning.
            try:
                validator = SocketFactsValidator()
            except Exception:
                validator = None
                logger.warning('jsonschema not available; skipping connector result validation')

            # Basic extraction
            comps = results.get('components') or []
            notifs = results.get('notifications') or []

            # Validate structure when validator is available
            if validator is not None:
                try:
                    # Only validate the wrapper shape; the schema expects {'components': [...]}
                    wrapper = {'components': comps}
                    errs = validator.validate_data(wrapper)
                    if errs:
                        logger.error('Connector %s produced invalid components shape; errors: %s', name, errs)
                        # skip this connector's results
                        continue
                except Exception:
                    logger.exception('Failed to validate connector %s results; skipping', name)
                    continue

            # Ensure 'components' and 'notifications' types
            if not isinstance(comps, list):
                logger.warning("Connector %s returned invalid 'components' shape; expected list", name)
                comps = []
            if not isinstance(notifs, list):
                logger.warning("Connector %s returned invalid 'notifications' shape; expected list", name)
                notifs = []

            # Merge components

            for c in comps:
                try:
                    cid = c.get('id') or c.get('name') or str(id(c))
                    aggregated_components[cid] = c
                except Exception:
                    logger.debug('Skipping malformed component from connector %s', name)

            # Merge notifications: canonical table dicts {title, headers, rows}
            for item in notifs:
                try:
                    if not isinstance(item, dict):
                        logger.warning("Connector %s produced non-dict notification item; skipping: %s", name, repr(item))
                        continue
                    title = item.get('title')
                    headers = item.get('headers')
                    payload_rows = item.get('rows')

                    # If connector exposes helper to filter rows, use it
                    try:
                        if hasattr(connector, 'filter_notification_rows_by_severity') and callable(getattr(connector, 'filter_notification_rows_by_severity')) and isinstance(payload_rows, list):
                            try:
                                payload_rows = connector.filter_notification_rows_by_severity(payload_rows, headers)
                            except Exception:
                                logger.debug('Connector %s failed while filtering notification rows by severity; using original rows', name)
                    except Exception:
                        pass
                    if payload_rows is None or len(payload_rows) == 0:
                        # skip empty notifications
                        continue    

                    # Strict validation: require title (str), headers (list), rows (list)
                    if not title or not isinstance(title, str):
                        logger.warning("Connector %s produced notification without valid title; skipping: %s", name, repr(item))
                        continue
                    if not isinstance(headers, list):
                        logger.warning("Connector %s produced notification '%s' without valid 'headers' (expected list); skipping", name, title)
                        continue
                    if not isinstance(payload_rows, list):
                        logger.warning("Connector %s produced notification '%s' with invalid 'rows' (expected list); skipping", name, title)
                        continue

                    # Ensure each row is a list/tuple; if not, skip the entire notification
                    bad_row = False
                    for r in payload_rows:
                        if not isinstance(r, (list, tuple)):
                            bad_row = True
                            break
                    if bad_row:
                        logger.warning("Connector %s produced notification '%s' with non-list rows; skipping", name, title)
                        continue

                    existing = notifications_by_title.get(title)
                    if existing is None:
                        notifications_by_title[title] = {'headers': headers, 'rows': list(payload_rows)}
                    else:
                        existing_rows = existing.get('rows') or []
                        existing_rows.extend(payload_rows)
                        # preserve headers if already set, otherwise adopt
                        if not existing.get('headers') and headers:
                            existing['headers'] = headers
                        notifications_by_title[title] = existing
                except Exception:
                    logger.debug('Skipping malformed notification from connector %s', name, exc_info=True)

            logger.info(f"Connector {name} completed successfully")

        # Build final lists
        try:
            components_list = list(aggregated_components.values())
            notifications_list = []
            for title, payload in notifications_by_title.items():
                try:
                    rows = payload.get('rows') if isinstance(payload, dict) else None
                    # Skip entries that have no rows to avoid header-only notifications
                    if not rows:
                        continue
                    notifications_list.append({'title': title, 'headers': payload.get('headers'), 'rows': rows})
                except Exception:
                    # If payload malformed, skip it
                    continue

            logger.debug("Final aggregated components count=%d, notifications count=%d", len(components_list), len(notifications_list))
        except Exception:
            logger.exception('Failed to build final aggregated results')
            components_list = []
            notifications_list = []

        return {'components': components_list, 'notifications': notifications_list}
    
    def get_connector_info(self) -> Dict[str, Any]:
        """Get information about available connectors
        
        Returns:
            Dict containing connector information
        """
        info = {
            'available_connectors': {},
            'enabled_connectors': self.get_enabled_connectors(),
            'loaded_connectors': list(self.loaded_connectors.keys())
        }
        
        for name, config in self.connectors_config.get('connectors', {}).items():
            info['available_connectors'][name] = {
                'class': config.get('class'),
                'description': config.get('description'),
                'enabled_by_default': config.get('enabled_by_default', False),
                'parameters': config.get('parameters', [])
            }
        
        return info
    
    def get_cli_parameters(self) -> List[Dict[str, Any]]:
        """Get CLI parameters for all available connectors
        
        Returns:
            List of parameter configurations for CLI argument parsing
        """
        parameters = []
        
        for connector_config in self.connectors_config.get('connectors', {}).values():
            for param in connector_config.get('parameters', []):
                parameters.append(param)
        
        return parameters
