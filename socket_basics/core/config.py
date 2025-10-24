#!/usr/bin/env python3
"""
Configuration management for Socket Security Basics
Handles CLI arguments, environment variables, and provides a unified config object
"""

import argparse
import json
import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class Config:
    """Configuration object that provides unified access to all settings"""
    
    def __init__(self, config_dict: Dict[str, Any] | None = None, json_config_path: str | None = None):
        """Initialize configuration from dictionary, JSON file, or environment
        
        Args:
            config_dict: Optional configuration dictionary (takes precedence)
            json_config_path: Optional path to JSON configuration file
        """
        if config_dict is not None:
            # Use provided config dictionary directly
            self._config = config_dict
        elif json_config_path is not None:
            # Load from JSON file and merge with environment
            try:
                json_config = load_config_from_json(json_config_path)
                self._config = merge_json_and_env_config(json_config)
            except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
                logger = logging.getLogger(__name__)
                logger.error("Failed to load JSON config from %s: %s", json_config_path, e)
                # Fall back to merged config (includes Socket Basics API config)
                self._config = merge_json_and_env_config()
        else:
            # Default: merge environment config with Socket Basics API config
            self._config = merge_json_and_env_config()
        
        self._config = self._config
        
        # DEBUG: Log final configuration values
        logger = logging.getLogger(__name__)
        logger.debug("Final Config object created with key values:")
        logger.debug(f"  javascript_sast_enabled: {self._config.get('javascript_sast_enabled')}")
        logger.debug(f"  socket_tier_1_enabled: {self._config.get('socket_tier_1_enabled')}")
        logger.debug(f"  console_tabular_enabled: {self._config.get('console_tabular_enabled')}")
        logger.debug(f"  socket_org: {self._config.get('socket_org')}")
        logger.debug(f"  socket_api_key set: {bool(self._config.get('socket_api_key'))}")
        # Validate workspace path: warn and fall back to cwd when missing
        ws = Path(self._config.get('workspace', os.getcwd()))
        if not ws.exists():
            logging.getLogger(__name__).warning("Configured workspace does not exist: %s; falling back to current working directory", str(ws))
            ws = Path(os.getcwd())
        self.workspace = ws
        self.output_dir = Path(self._config.get('output_dir', self.workspace))
        self.scan_files = self._parse_scan_files(self._config.get('scan_files', ''))
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self._config[key] = value
    
    def _parse_scan_files(self, scan_files_str: str) -> List[str]:
        """Parse comma-separated scan files into a list"""
        if not scan_files_str.strip():
            return []
        return [f.strip() for f in scan_files_str.split(',') if f.strip()]
    
    def get_scan_targets(self) -> List[str]:
        """Determine files to scan based on configuration"""
        # If explicit 'scan_all' set, return workspace directory
        if self.get('scan_all', False):
            return [str(self.workspace)]

        # If user provided specific files to scan, validate their existence
        if self.scan_files:
            targets = [self.workspace / f for f in self.scan_files]
            valid = []
            for t in targets:
                if t.exists():
                    valid.append(str(t))
                else:
                    logging.getLogger(__name__).warning("Scan target does not exist: %s", str(t))
            return valid

        # Default: scan the workspace itself
        return [str(self.workspace)]
    
    def get_action_for_severity(self, severity: str) -> str:
        """Map severity to action according to security policy"""
        # Normalize severity to lowercase for consistent mapping
        severity_lower = severity.lower()
        
        # Security policy mapping
        if severity_lower == 'critical':
            return 'error'
        elif severity_lower == 'high':
            return 'warn'
        elif severity_lower in ['medium', 'middle', 'moderate']:
            return 'monitor'
        elif severity_lower == 'low':
            return 'ignore'
        else:
            # Default action for unknown severities
            return 'monitor'
    
    @property
    def repo(self) -> str:
        """Get repository name"""
        return str(self.get('repo', ''))
    
    @property
    def branch(self) -> str:
        """Get branch name"""
        return str(self.get('branch', ''))
    
    @property
    def commit_hash(self) -> str:
        """Get commit hash (optional)"""
        return str(self.get('commit_hash', ''))
    
    @property
    def is_default_branch(self) -> bool:
        """Check if current branch is the default branch"""
        return bool(self.get('is_default_branch', False))
    
    def is_notifier_available(self, notifier: str) -> bool:
        """Check if a notifier is available based on Socket plan"""
        available_notifiers = self.get('available_notifiers', ['console_tabular', 'console_json'])
        if not isinstance(available_notifiers, list):
            available_notifiers = ['console_tabular', 'console_json']
        return notifier in available_notifiers
    
    def get_socket_plan_info(self) -> Dict[str, Any]:
        """Get Socket plan information"""
        return {
            'plan': self.get('socket_plan', 'free'),
            'has_enterprise': self.get('socket_has_enterprise', False),
            'available_notifiers': self.get('available_notifiers', ['console_tabular', 'console_json'])
        }
    
    def should_run_sast(self) -> bool:
        """Check if any SAST language is enabled dynamically"""
        try:
            # Get SAST parameters dynamically from connectors config
            connectors_config = load_connectors_config()
            opengrep_config = connectors_config.get('connectors', {}).get('opengrep', {})
            
            for param in opengrep_config.get('parameters', []):
                param_name = param.get('name', '')
                if 'sast_enabled' in param_name and self.get(param_name, False):
                    return True
                    
            return False
        except Exception:
            # Fallback to hardcoded check if YAML loading fails
            sast_langs = [
                'python_sast_enabled', 'golang_sast_enabled', 'javascript_sast_enabled',
                'typescript_sast_enabled', 'java_sast_enabled', 'ruby_sast_enabled',
                'dotnet_sast_enabled', 'scala_sast_enabled', 'kotlin_sast_enabled', 
                'rust_sast_enabled', 'c_sast_enabled', 'cpp_sast_enabled', 
                'php_sast_enabled', 'swift_sast_enabled', 'elixir_sast_enabled', 
                'erlang_sast_enabled', 'csharp_sast_enabled'
            ]
            return any(self.get(lang, False) for lang in sast_langs)
    
    def build_opengrep_rules(self) -> List[str]:
        """Build list of rule files based on enabled languages"""
        # Explicit mapping from connector boolean flags to bundled rule filenames.
        # Exclude languages for which we don't ship rule files (objective-c, erlang).
        language_rules = {
            'python_sast_enabled': 'python.yml',
            'go_sast_enabled': 'go.yml',
            'golang_sast_enabled': 'go.yml',
            'javascript_sast_enabled': 'javascript_typescript.yml',
            'typescript_sast_enabled': 'javascript_typescript.yml',
            'java_sast_enabled': 'java.yml',
            'ruby_sast_enabled': 'ruby.yml',
            'csharp_sast_enabled': 'dotnet.yml',
            'dotnet_sast_enabled': 'dotnet.yml',
            'scala_sast_enabled': 'scala.yml',
            'kotlin_sast_enabled': 'kotlin.yml',
            'rust_sast_enabled': 'rust.yml',
            'c_sast_enabled': 'c_cpp.yml',
            'cpp_sast_enabled': 'c_cpp.yml',
            'php_sast_enabled': 'php.yml',
            'swift_sast_enabled': 'swift.yml',
            'elixir_sast_enabled': 'elixir.yml'
        }

        # If user has requested 'all rules', run the full rule files for the languages
        # that are enabled. If no specific languages are enabled but --all-languages is
        # set, fall back to all bundled rule files. If neither is set, return empty
        # to allow upstream logic to skip scanning.
        if self.get('all_rules_enabled', False):
            rule_files = []
            for flag, filename in language_rules.items():
                if self.get(flag, False):
                    if filename not in rule_files:
                        rule_files.append(filename)

            # If no specific language flags were enabled, but user set --all-languages,
            # return all bundled rules.
            if not rule_files:
                if self.get('all_languages_enabled', False):
                    try:
                        base_dir = Path(__file__).parent.parent
                        rules_dir = base_dir / 'rules'
                        found = [p.name for p in rules_dir.glob('*.yml') if p.is_file()]
                        excluded = {'objective-c.yml', 'erlang.yml'}
                        return [f for f in found if f not in excluded]
                    except Exception:
                        return list({v for v in language_rules.values()})
                # No languages enabled -> nothing to run
                return []

            return rule_files

        rule_files = []
        for flag, filename in language_rules.items():
            if self.get(flag, False):
                if filename not in rule_files:
                    rule_files.append(filename)

        return rule_files

    def get_enabled_rules_for_language(self, language: str) -> List[str]:
        """Get list of enabled rules for a specific language"""
        rules_param = f"{language}_enabled_rules"
        rules_str = self.get(rules_param, "")
        
        if not rules_str or not rules_str.strip():
            return []
        
        return [rule.strip() for rule in rules_str.split(',') if rule.strip()]

    def build_filtered_opengrep_rules(self) -> Dict[str, List[str]]:
        """Build mapping of rule files to specific rules that should be enabled"""
        # Map connector flags to (rule filename, parameter name) so we can
        # look up the user-specified enabled rules for that language.
        language_rule_mapping = {
            'python_sast_enabled': ('python.yml', 'python_enabled_rules'),
            'go_sast_enabled': ('go.yml', 'go_enabled_rules'),
            'golang_sast_enabled': ('go.yml', 'go_enabled_rules'),
            'javascript_sast_enabled': ('javascript_typescript.yml', 'javascript_enabled_rules'),
            'typescript_sast_enabled': ('javascript_typescript.yml', 'javascript_enabled_rules'),
            'java_sast_enabled': ('java.yml', 'java_enabled_rules'),
            'ruby_sast_enabled': ('ruby.yml', 'ruby_enabled_rules'),
            'csharp_sast_enabled': ('dotnet.yml', 'csharp_enabled_rules'),
            'dotnet_sast_enabled': ('dotnet.yml', 'dotnet_enabled_rules'),
            'scala_sast_enabled': ('scala.yml', 'scala_enabled_rules'),
            'kotlin_sast_enabled': ('kotlin.yml', 'kotlin_enabled_rules'),
            'rust_sast_enabled': ('rust.yml', 'rust_enabled_rules'),
            'c_sast_enabled': ('c_cpp.yml', 'c_enabled_rules'),
            'cpp_sast_enabled': ('c_cpp.yml', 'cpp_enabled_rules'),
            'php_sast_enabled': ('php.yml', 'php_enabled_rules'),
            'swift_sast_enabled': ('swift.yml', 'swift_enabled_rules'),
            'elixir_sast_enabled': ('elixir.yml', 'elixir_enabled_rules')
        }

        rule_file_filters: Dict[str, set] = {}

        for flag, (rule_file, rules_param) in language_rule_mapping.items():
            if not self.get(flag, False):
                continue

            # rules_param is the exact parameter name defined in connectors.yaml
            enabled_rules = self.get(rules_param, "")
            if not enabled_rules:
                continue

            for r in [s.strip() for s in enabled_rules.split(',') if s.strip()]:
                if rule_file not in rule_file_filters:
                    rule_file_filters[rule_file] = set()
                rule_file_filters[rule_file].add(r)

        # Convert sets to lists for output
        return {k: list(v) for k, v in rule_file_filters.items()}

    def get_custom_rules_path(self) -> Optional[Path]:
        """Get the absolute path to custom SAST rules directory.
        
        Returns path relative to workspace if workspace is set, otherwise relative to cwd.
        Returns None if custom rules are not enabled or path doesn't exist.
        """
        if not self.get('use_custom_sast_rules', False):
            return None
        
        custom_path_str = self.get('custom_sast_rule_path', 'custom_rules')
        if not custom_path_str:
            return None
        
        # Determine base path
        try:
            if hasattr(self, 'workspace') and self.workspace:
                base_path = Path(self.workspace)
            else:
                base_path = Path.cwd()
        except Exception:
            base_path = Path.cwd()
        
        # Resolve custom rules path
        custom_path = base_path / custom_path_str
        
        # Check if path exists
        if not custom_path.exists():
            logger.warning(f"Custom SAST rules path does not exist: {custom_path}")
            return None
        
        if not custom_path.is_dir():
            logger.warning(f"Custom SAST rules path is not a directory: {custom_path}")
            return None
        
        return custom_path


# Centralized environment variable getters
# All connectors and notifiers should use these methods instead of calling os.getenv directly

def get_env_with_fallbacks(*env_vars: str, default: str = '') -> str:
    """Get environment variable value with multiple fallback options.
    
    Args:
        *env_vars: Variable number of environment variable names to check (in priority order)
        default: Default value if none of the env vars are set
        
    Returns:
        First non-empty environment variable value found, or default
    """
    for env_var in env_vars:
        value = os.getenv(env_var)
        if value:
            return value
    return default


def get_github_token() -> str:
    """Get GitHub token from environment variables."""
    return get_env_with_fallbacks('GITHUB_TOKEN', 'INPUT_GITHUB_TOKEN')


def get_github_repository() -> str:
    """Get GitHub repository from environment variables."""
    return get_env_with_fallbacks('GITHUB_REPOSITORY', 'INPUT_GITHUB_REPOSITORY')


def get_github_pr_number() -> str:
    """Get GitHub PR number from environment variables."""
    return get_env_with_fallbacks('GITHUB_PR_NUMBER', 'INPUT_PR_NUMBER')


def get_slack_webhook_url() -> str:
    """Get Slack webhook URL from environment variables."""
    return get_env_with_fallbacks('SLACK_WEBHOOK_URL', 'INPUT_SLACK_WEBHOOK_URL')


def get_webhook_url() -> str:
    """Get generic webhook URL from environment variables."""
    return get_env_with_fallbacks('WEBHOOK_URL', 'INPUT_WEBHOOK_URL')


def get_ms_sentinel_workspace_id() -> str:
    """Get Microsoft Sentinel workspace ID from environment variables."""
    return get_env_with_fallbacks('MS_SENTINEL_WORKSPACE_ID', 'INPUT_MS_SENTINEL_WORKSPACE_ID')


def get_ms_sentinel_shared_key() -> str:
    """Get Microsoft Sentinel shared key from environment variables."""
    return get_env_with_fallbacks('MS_SENTINEL_SHARED_KEY', 'INPUT_MS_SENTINEL_SHARED_KEY')


def get_ms_sentinel_collector_url() -> str:
    """Get Microsoft Sentinel collector URL from environment variables."""
    return get_env_with_fallbacks('MS_SENTINEL_COLLECTOR_URL', 'INPUT_MS_SENTINEL_COLLECTOR_URL')


def get_jira_url() -> str:
    """Get JIRA URL from environment variables."""
    return get_env_with_fallbacks('JIRA_URL', 'INPUT_JIRA_URL')


def get_jira_project() -> str:
    """Get JIRA project from environment variables."""
    return get_env_with_fallbacks('JIRA_PROJECT', 'INPUT_JIRA_PROJECT')


def get_jira_email() -> str:
    """Get JIRA email from environment variables."""
    return get_env_with_fallbacks('JIRA_EMAIL', 'INPUT_JIRA_EMAIL')


def get_jira_api_token() -> str:
    """Get JIRA API token from environment variables."""
    return get_env_with_fallbacks('JIRA_API_TOKEN', 'INPUT_JIRA_API_TOKEN')


def get_sumologic_http_source_url() -> str:
    """Get SumoLogic HTTP source URL from environment variables."""
    return get_env_with_fallbacks('SUMO_LOGIC_HTTP_SOURCE_URL', 'INPUT_SUMO_LOGIC_HTTP_SOURCE_URL')


def get_sumologic_endpoint() -> str:
    """Get SumoLogic endpoint from environment variables."""
    return get_env_with_fallbacks('SUMOLOGIC_ENDPOINT', 'INPUT_SUMOLOGIC_ENDPOINT')


def get_msteams_webhook_url() -> str:
    """Get Microsoft Teams webhook URL from environment variables."""
    return get_env_with_fallbacks('MSTEAMS_WEBHOOK_URL', 'INPUT_MSTEAMS_WEBHOOK_URL')


def get_socket_basics_severities() -> str:
    """Get Socket Basics severities from environment variables."""
    return get_env_with_fallbacks('SOCKET_BASICS_SEVERITIES', 'INPUT_FINDING_SEVERITIES')


def get_github_workspace() -> str:
    """Get GitHub workspace from environment variables."""
    return get_env_with_fallbacks('GITHUB_WORKSPACE', default=os.getcwd())


def load_config_from_json(json_path: str) -> Dict[str, Any]:
    """Load configuration from a JSON file
    
    Args:
        json_path: Path to the JSON configuration file
        
    Returns:
        Dictionary containing the configuration from the JSON file
        
    Raises:
        FileNotFoundError: If the JSON file doesn't exist
        json.JSONDecodeError: If the JSON file is malformed
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validate that the loaded config is a dictionary
        if not isinstance(config, dict):
            raise ValueError(f"JSON config file must contain a JSON object, got {type(config).__name__}")
            
        logger = logging.getLogger(__name__)
        logger.info("Successfully loaded configuration from JSON file: %s", json_path)
        
        return config
        
    except FileNotFoundError:
        raise FileNotFoundError(f"JSON configuration file not found: {json_path}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in configuration file {json_path}: {e.msg}", e.doc, e.pos)


def load_config_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables dynamically from connectors.yaml"""
    config = {
        # Core workspace settings
        'workspace': os.getenv('GITHUB_WORKSPACE', os.getcwd()),
        'output_dir': os.getenv('OUTPUT_DIR', os.getcwd()),
        
        # Scan scope
        'scan_all': os.getenv('INPUT_SCAN_ALL', 'false').lower() == 'true',
        'scan_files': os.getenv('INPUT_SCAN_FILES', ''),
        
        # Core Socket API configuration (top-level, like workspace)
        'socket_org': (
            os.getenv('SOCKET_ORG', '') or 
            os.getenv('SOCKET_ORG_SLUG', '') or
            os.getenv('INPUT_SOCKET_ORG', '')
        ),
        'socket_api_key': (
            os.getenv('SOCKET_SECURITY_API_KEY', '') or 
            os.getenv('SOCKET_SECURITY_API_TOKEN', '') or
            os.getenv('SOCKET_API_KEY', '') or
            os.getenv('INPUT_SOCKET_SECURITY_API_KEY', '') or
            os.getenv('INPUT_SOCKET_API_KEY', '')
        ),
        
        # Socket plan detection (will be populated later in merge process)
        'socket_plan': '',
        'socket_has_enterprise': False,
        'available_notifiers': ['console_tabular', 'console_json'],  # Default free plan notifiers
        
        # OpenGrep configuration (optional override for custom rules)
        'opengrep_rules_dir': os.getenv('INPUT_OPENGREP_RULES_DIR', ''),
        
        # GitHub environment variables for discovery functions
        'github_actor': os.getenv('GITHUB_ACTOR', ''),
        'github_pr_number': os.getenv('GITHUB_PR_NUMBER', ''),
        'github_head_ref': os.getenv('GITHUB_HEAD_REF', ''),
        'github_event_path': os.getenv('GITHUB_EVENT_PATH', ''),
        'github_sha': os.getenv('GITHUB_SHA', ''),
        'github_repository': os.getenv('GITHUB_REPOSITORY', ''),
        'github_ref_name': os.getenv('GITHUB_REF_NAME', ''),
    }
    
    # Dynamically load connector parameters from YAML configuration
    try:
        connectors_config = load_connectors_config()
        
        for connector_name, connector_config in connectors_config.get('connectors', {}).items():
            for param in connector_config.get('parameters', []):
                param_name = param.get('name')
                env_variable = param.get('env_variable')
                param_type = param.get('type', 'str')
                default_value = param.get('default', False if param_type == 'bool' else '')
                
                if param_name and env_variable:
                    env_value = os.getenv(env_variable)
                    
                    if env_value is not None:
                        if param_type == 'bool':
                            val = env_value.lower() == 'true'
                            config[param_name] = val
                            # honor 'enables' and 'disables' metadata from connectors.yaml
                            try:
                                if val and 'enables' in param:
                                    for enabled in param.get('enables', []):
                                        config[enabled] = True
                                if val and 'disables' in param:
                                    for disabled in param.get('disables', []):
                                        config[disabled] = False
                                # if the boolean flag is false but a default was provided,
                                # do not automatically flip related params; explicit true flags
                                # drive enable/disable propagation.
                            except Exception:
                                pass
                        elif param_type == 'int':
                            try:
                                config[param_name] = int(env_value)
                            except ValueError:
                                config[param_name] = default_value
                        else:  # str type
                            config[param_name] = env_value
                    else:
                        # Use default value if environment variable is not set
                        config[param_name] = default_value
                        
    except Exception as e:
        logging.getLogger(__name__).warning("Warning: Error loading dynamic config from environment: %s", e)
    
    # Also load notification parameters from notifications.yaml so CLI/env can enable them
    try:
        base_dir = Path(__file__).parent.parent
        notif_path = base_dir / 'notifications.yaml'
        if notif_path.exists():
            with open(notif_path, 'r') as f:
                notif_cfg = yaml.safe_load(f) or {}
            for n_name, n_cfg in (notif_cfg.get('notifiers') or {}).items():
                for param in n_cfg.get('parameters', []) or []:
                    p_name = param.get('name')
                    env_var = param.get('env_variable')
                    p_type = param.get('type', 'str')
                    default_value = param.get('default', '' if p_type != 'bool' else False)

                    if p_name and env_var:
                        env_value = os.getenv(env_var)
                        if env_value is not None:
                            if p_type == 'bool':
                                config[p_name] = env_value.lower() == 'true'
                            elif p_type == 'int':
                                try:
                                    config[p_name] = int(env_value)
                                except ValueError:
                                    logging.getLogger(__name__).warning(
                                        "Invalid integer for %s (env %s): %s; using default %s",
                                        p_name, env_var, env_value, default_value
                                    )
                                    config[p_name] = default_value
                            else:
                                config[p_name] = env_value
                        else:
                            config[p_name] = default_value
    except Exception:
        # Best-effort; do not fail on notification parsing
        pass
    
    # Auto-enable scanning when values are provided (removes need for separate enabled flags)
    # If container_images has a value, enable image scanning
    if config.get('container_images'):
        config['trivy_image_enabled'] = True
        config['container_image_scanning_enabled'] = True
    
    # If dockerfiles has a value, enable Dockerfile scanning
    if config.get('dockerfiles'):
        config['trivy_dockerfile_enabled'] = True
        config['dockerfile_scanning_enabled'] = True

    return config


def load_socket_basics_config() -> Dict[str, Any] | None:
    """Load Socket Basics configuration from Socket API if organization has enterprise plan
    
    Returns:
        Socket Basics configuration dictionary if available, None otherwise
    """
    logger = logging.getLogger(__name__)
    logger.debug(" load_socket_basics_config() called")
    
    # Check if Socket API integration is available
    # Support both direct env vars and GitHub Actions INPUT_ prefixed vars
    api_key = (
        os.environ.get('SOCKET_SECURITY_API_KEY')
        or os.environ.get('SOCKET_SECURITY_API_TOKEN')
        or os.environ.get('INPUT_SOCKET_SECURITY_API_KEY')
    )
    
    logger.debug(f" API key check - SOCKET_SECURITY_API_KEY set: {bool(os.environ.get('SOCKET_SECURITY_API_KEY'))}")
    logger.debug(f" API key check - SOCKET_SECURITY_API_TOKEN set: {bool(os.environ.get('SOCKET_SECURITY_API_TOKEN'))}")
    logger.debug(f" API key check - INPUT_SOCKET_SECURITY_API_KEY set: {bool(os.environ.get('INPUT_SOCKET_SECURITY_API_KEY'))}")
    logger.debug(f" Final api_key available: {bool(api_key)}")
    
    if not api_key:
        logger.info("Socket API key not detected - running in free plan mode (limited features)")
        logger.debug("Checked: SOCKET_SECURITY_API_KEY, SOCKET_SECURITY_API_TOKEN, INPUT_SOCKET_SECURITY_API_KEY")
        return {
            'socket_plan': 'free',
            'socket_has_enterprise': False,
            'available_notifiers': ['console_tabular', 'console_json']
        }
    
    logger.info("Socket API key detected - attempting to load dashboard configuration")
    
    # Support both direct env vars and GitHub Actions INPUT_ prefixed vars
    org_slug = (
        os.environ.get('SOCKET_ORG_SLUG')
        or os.environ.get('SOCKET_ORG')
        or os.environ.get('INPUT_SOCKET_ORG')
    )
    
    logger.debug(f" SOCKET_ORG_SLUG: {os.environ.get('SOCKET_ORG_SLUG', 'not set')}")
    logger.debug(f" SOCKET_ORG: {os.environ.get('SOCKET_ORG', 'not set')}")
    logger.debug(f" INPUT_SOCKET_ORG: {os.environ.get('INPUT_SOCKET_ORG', 'not set')}")
    logger.debug(f" org_slug from env: {org_slug or 'not set - will auto-discover'}")
    
    try:
        # Import socketdev here to avoid import errors if not installed
        from socketdev import socketdev
        
        # Initialize SDK
        sdk = socketdev(token=api_key, timeout=100)
        
        # Get organizations and find the right one or auto-discover
        orgs = sdk.org.get()
        target_org = None
        
        logger.debug(f" Found {len(orgs.get('organizations', {}))} organizations in API response")
        
        if len(orgs) > 0:
            if org_slug:
                # Look for specific organization
                logger.debug(f" Looking for specific organization: {org_slug}")
                for org_key in orgs['organizations']:
                    org = orgs['organizations'][org_key]
                    if org.get('slug') == org_slug:
                        target_org = org
                        logger.info(f"Found organization '{org_slug}' with plan: {org.get('plan', '')}")
                        break
            else:
                # Auto-discover first organization
                logger.debug(" Auto-discovering organization (no SOCKET_ORG set)")
                for org_key in orgs['organizations']:
                    org = orgs['organizations'][org_key]
                    target_org = org
                    org_slug = org['slug']
                    logger.info(f"Auto-discovered organization '{org_slug}' with plan: {org.get('plan', '')}")
                    break
        
        if not target_org or not org_slug:
            logger.warning("No suitable organization found in API response")
            return None
        
        # Check if organization has enterprise plan
        plan = target_org.get('plan', '')
        has_enterprise = plan.startswith('enterprise')
        
        # Always return plan information, even for non-enterprise plans
        base_plan_config = {
            'socket_plan': plan,
            'socket_has_enterprise': has_enterprise,
            'socket_org': org_slug,  # Populate discovered org
            'available_notifiers': ['console_tabular', 'console_json'] if not has_enterprise else [
                'console_tabular', 'console_json', 'slack', 'ms_teams', 'jira', 
                'webhook', 'sumologic', 'ms_sentinel', 'github_pr', 'json_notifier'
            ]
        }
        
        if not has_enterprise:
            logger.info(f"Organization '{org_slug}' does not have enterprise plan, returning basic config only")
            return base_plan_config
        
        # Get Socket Basics configuration
        basics_config_response = sdk.basics.get_config(org_slug=org_slug)
        logger.info(f"Retrieved Socket Basics config for enterprise organization '{org_slug}'")
        
        # Convert response to dictionary if needed
        basics_config = None
        if isinstance(basics_config_response, dict):
            basics_config = basics_config_response
        elif hasattr(basics_config_response, '__dict__'):
            basics_config = basics_config_response.__dict__
        elif hasattr(basics_config_response, 'to_dict') and callable(getattr(basics_config_response, 'to_dict')):
            basics_config = basics_config_response.to_dict()
        else:
            # Try to convert to dict using json serialization
            try:
                basics_config = json.loads(json.dumps(basics_config_response, default=str))
            except Exception:
                logger.warning("Could not convert Socket Basics config response to dictionary")
                return None
        
        # If additionalParameters contains JSON, parse and merge it
        if isinstance(basics_config, dict) and basics_config.get('additionalParameters'):
            logger.debug(" Found additionalParameters in Socket Basics config")
            logger.debug(f" additionalParameters content: {basics_config['additionalParameters']}")
            try:
                additional_params = json.loads(basics_config['additionalParameters'])
                logger.debug(f" Parsed additionalParameters: {json.dumps(additional_params, indent=2)}")
                if isinstance(additional_params, dict):
                    merged_config = {**base_plan_config, **basics_config, **additional_params}
                    logger.debug(" Merged additionalParameters into Socket Basics config")
                    logger.debug(f" Final merged config keys: {list(merged_config.keys())}")
                    logger.debug(f" Key config values - javascript_sast_enabled: {merged_config.get('javascript_sast_enabled')}, socket_tier_1_enabled: {merged_config.get('socket_tier_1_enabled')}, console_tabular_enabled: {merged_config.get('console_tabular_enabled')}")
                    return merged_config
            except json.JSONDecodeError as e:
                logger.warning(f"additionalParameters is not valid JSON: {e}, using base config")
                logger.debug(f" Raw additionalParameters that failed to parse: {repr(basics_config['additionalParameters'])}")
        
        # Return basic config merged with plan information
        return {**base_plan_config, **basics_config} if isinstance(basics_config, dict) else base_plan_config
        
    except ImportError:
        logger.debug("socketdev package not installed, skipping Socket Basics config load")
        return None
    except Exception as e:
        logger.warning(f"Error loading Socket Basics config: {e}")
        return None


def load_explicit_env_config() -> Dict[str, Any]:
    """Load only explicitly set environment variables (not defaults)"""
    logger = logging.getLogger(__name__)
    config = {}
    
    # Log which API key sources are available for debugging
    api_key_sources = {
        'SOCKET_SECURITY_API_KEY': bool(os.environ.get('SOCKET_SECURITY_API_KEY')),
        'SOCKET_SECURITY_API_TOKEN': bool(os.environ.get('SOCKET_SECURITY_API_TOKEN')),
        'INPUT_SOCKET_SECURITY_API_KEY': bool(os.environ.get('INPUT_SOCKET_SECURITY_API_KEY')),
    }
    found_sources = [k for k, v in api_key_sources.items() if v]
    if found_sources:
        logger.debug(f"API key sources detected: {', '.join(found_sources)}")
    
    # Core settings - only if explicitly set
    if 'GITHUB_WORKSPACE' in os.environ:
        config['workspace'] = os.environ['GITHUB_WORKSPACE']
    if 'OUTPUT_DIR' in os.environ:
        config['output_dir'] = os.environ['OUTPUT_DIR']
    if 'INPUT_SCAN_ALL' in os.environ:
        config['scan_all'] = os.environ['INPUT_SCAN_ALL'].lower() == 'true'
    if 'INPUT_SCAN_FILES' in os.environ:
        config['scan_files'] = os.environ['INPUT_SCAN_FILES']
    if 'INPUT_OPENGREP_RULES_DIR' in os.environ:
        config['opengrep_rules_dir'] = os.environ['INPUT_OPENGREP_RULES_DIR']
    
    # Dynamically load connector parameters from YAML configuration - only if explicitly set
    try:
        connectors_config = load_connectors_config()
        
        for connector_name, connector_config in connectors_config.get('connectors', {}).items():
            for param in connector_config.get('parameters', []):
                param_name = param.get('name')
                env_variable = param.get('env_variable')
                param_type = param.get('type', 'str')
                
                if param_name and env_variable and env_variable in os.environ:
                    env_value = os.environ[env_variable]
                    
                    if param_type == 'bool':
                        val = env_value.lower() == 'true'
                        config[param_name] = val
                        # honor 'enables' and 'disables' metadata from connectors.yaml
                        try:
                            if val and 'enables' in param:
                                for enabled in param.get('enables', []):
                                    config[enabled] = True
                            if val and 'disables' in param:
                                for disabled in param.get('disables', []):
                                    config[disabled] = False
                        except Exception:
                            pass
                    elif param_type == 'int':
                        try:
                            config[param_name] = int(env_value)
                        except ValueError:
                            pass  # Skip invalid values
                    else:  # str type
                        config[param_name] = env_value
                        
    except Exception as e:
        logging.getLogger(__name__).warning("Warning: Error loading explicit env config: %s", e)
    
    return config


def normalize_api_config(api_config: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize camelCase API keys to snake_case internal format.
    
    Maps Socket Basics API response keys (camelCase) to internal config keys (snake_case).
    This allows the API to use camelCase while maintaining snake_case internally.
    
    Args:
        api_config: Configuration dictionary from Socket Basics API (camelCase)
        
    Returns:
        Normalized configuration dictionary (snake_case)
    """
    # Mapping from camelCase API keys to snake_case internal keys
    API_TO_INTERNAL_MAP = {
        # Console/Output
        'consoleTabularEnabled': 'console_tabular_enabled',
        'consoleJsonEnabled': 'console_json_enabled',
        'verbose': 'verbose',
        
        # SAST Language Flags
        'allLanguagesEnabled': 'all_languages_enabled',
        'pythonSastEnabled': 'python_sast_enabled',
        'javascriptSastEnabled': 'javascript_sast_enabled',
        'typescriptSastEnabled': 'typescript_sast_enabled',
        'goSastEnabled': 'go_sast_enabled',
        'golangSastEnabled': 'golang_sast_enabled',
        'javaSastEnabled': 'java_sast_enabled',
        'phpSastEnabled': 'php_sast_enabled',
        'rubySastEnabled': 'ruby_sast_enabled',
        'csharpSastEnabled': 'csharp_sast_enabled',
        'dotnetSastEnabled': 'dotnet_sast_enabled',
        'cSastEnabled': 'c_sast_enabled',
        'cppSastEnabled': 'cpp_sast_enabled',
        'kotlinSastEnabled': 'kotlin_sast_enabled',
        'scalaSastEnabled': 'scala_sast_enabled',
        'swiftSastEnabled': 'swift_sast_enabled',
        'rustSastEnabled': 'rust_sast_enabled',
        'elixirSastEnabled': 'elixir_sast_enabled',
        
        # SAST Rules Configuration
        'allRulesEnabled': 'all_rules_enabled',
        'pythonEnabledRules': 'python_enabled_rules',
        'pythonDisabledRules': 'python_disabled_rules',
        'javascriptEnabledRules': 'javascript_enabled_rules',
        'javascriptDisabledRules': 'javascript_disabled_rules',
        'goEnabledRules': 'go_enabled_rules',
        'goDisabledRules': 'go_disabled_rules',
        'javaEnabledRules': 'java_enabled_rules',
        'javaDisabledRules': 'java_disabled_rules',
        'kotlinEnabledRules': 'kotlin_enabled_rules',
        'kotlinDisabledRules': 'kotlin_disabled_rules',
        'scalaEnabledRules': 'scala_enabled_rules',
        'scalaDisabledRules': 'scala_disabled_rules',
        'phpEnabledRules': 'php_enabled_rules',
        'phpDisabledRules': 'php_disabled_rules',
        'rubyEnabledRules': 'ruby_enabled_rules',
        'rubyDisabledRules': 'ruby_disabled_rules',
        'csharpEnabledRules': 'csharp_enabled_rules',
        'csharpDisabledRules': 'csharp_disabled_rules',
        'dotnetEnabledRules': 'dotnet_enabled_rules',
        'dotnetDisabledRules': 'dotnet_disabled_rules',
        'cEnabledRules': 'c_enabled_rules',
        'cDisabledRules': 'c_disabled_rules',
        'cppEnabledRules': 'cpp_enabled_rules',
        'cppDisabledRules': 'cpp_disabled_rules',
        'swiftEnabledRules': 'swift_enabled_rules',
        'swiftDisabledRules': 'swift_disabled_rules',
        'rustEnabledRules': 'rust_enabled_rules',
        'rustDisabledRules': 'rust_disabled_rules',
        'elixirEnabledRules': 'elixir_enabled_rules',
        'elixirDisabledRules': 'elixir_disabled_rules',
        
        # OpenGrep/SAST Configuration
        'openGrepNotificationMethod': 'opengrep_notification_method',
        
        # Socket Tier 1
        'socketTier1Enabled': 'socket_tier_1_enabled',
        'socketAdditionalParams': 'socket_additional_params',
        
        # Secret Scanning
        'secretScanningEnabled': 'secret_scanning_enabled',
        'disableAllSecrets': 'disable_all_secrets',
        'trufflehogExcludeDir': 'trufflehog_exclude_dir',
        'trufflehogShowUnverified': 'trufflehog_show_unverified',
        'trufflehogNotificationMethod': 'trufflehog_notification_method',
        
        # Container/Image Scanning
        'containerImagesToScan': 'container_images',
        'dockerfiles': 'dockerfiles',
        'trivyImageEnabled': 'trivy_image_enabled',
        'trivyDockerfileEnabled': 'trivy_dockerfile_enabled',
        'trivyNotificationMethod': 'trivy_notification_method',
        'trivyDisabledRules': 'trivy_disabled_rules',
        'trivyImageScanningDisabled': 'trivy_image_scanning_disabled',
        
        # Notifier Configuration
        'slackWebhookUrl': 'slack_webhook_url',
        'webhookUrl': 'webhook_url',
        'msSentinelWorkspaceId': 'ms_sentinel_workspace_id',
        'msSentinelKey': 'ms_sentinel_shared_key',
        'sumologicEndpoint': 'sumologic_endpoint',
        'jiraUrl': 'jira_url',
        'jiraProject': 'jira_project',
        'jiraEmail': 'jira_email',
        'jiraApiToken': 'jira_api_token',
        'githubToken': 'github_token',
        'githubApiUrl': 'github_api_url',
        'msteamsWebhookUrl': 'msteams_webhook_url',
        
        # S3 Configuration
        's3Enabled': 's3_enabled',
        's3Bucket': 's3_bucket',
        's3AccessKey': 's3_access_key',
        's3SecretKey': 's3_secret_key',
        's3Endpoint': 's3_endpoint',
        's3Region': 's3_region',
        
        # Additional Features
        'externalCveScanningEnabled': 'external_cve_scanning_enabled',
        'socketScanningEnabled': 'socket_scanning_enabled',
        'socketScaEnabled': 'socket_sca_enabled',
        'additionalParameters': 'additional_parameters',
    }
    
    normalized = {}
    logger = logging.getLogger(__name__)
    
    for api_key, value in api_config.items():
        # Check if we have a mapping for this key
        if api_key in API_TO_INTERNAL_MAP:
            internal_key = API_TO_INTERNAL_MAP[api_key]
            normalized[internal_key] = value
            logger.debug(f" Mapped API key '{api_key}' -> '{internal_key}' = {value}")
        else:
            # Pass through unmapped keys as-is (for plan info, etc.)
            normalized[api_key] = value
            logger.debug(f" Pass-through key '{api_key}' = {value}")
    
    # Special handling: if containerImagesToScan or dockerfiles have values, enable scanning
    # This eliminates the need for separate *_enabled flags
    if normalized.get('container_images'):
        normalized['trivy_image_enabled'] = True
        normalized['container_image_scanning_enabled'] = True  # For backward compatibility
        logger.debug(" Auto-enabled trivy_image_enabled because container_images is set")
    
    if normalized.get('dockerfiles'):
        normalized['trivy_dockerfile_enabled'] = True
        normalized['dockerfile_scanning_enabled'] = True  # For backward compatibility
        logger.debug(" Auto-enabled trivy_dockerfile_enabled because dockerfiles is set")
    
    # Handle trivy notification method mapping
    if 'trivy_notification_method' in normalized:
        normalized['notification_method'] = normalized['trivy_notification_method']
    
    # Handle trufflehog notification method mapping
    if 'trufflehog_notification_method' in normalized:
        if 'notification_method' not in normalized:
            normalized['notification_method'] = normalized['trufflehog_notification_method']
    
    # Handle opengrep notification method mapping
    if 'opengrep_notification_method' in normalized:
        if 'notification_method' not in normalized:
            normalized['notification_method'] = normalized['opengrep_notification_method']
    
    return normalized


def merge_json_and_env_config(json_config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Merge JSON configuration with environment variables
    
    Priority order (highest to lowest):
    1. CLI options (handled separately via argparse, highest priority)
    2. Socket Basics API config / JSON config (dashboard settings)
    3. Environment variables from action.yml (lowest priority - defaults)
    
    Args:
        json_config: Optional dictionary from JSON config file
        
    Returns:
        Merged configuration dictionary
    """
    # Start with environment defaults (lowest priority)
    config = load_config_from_env()
    
    # Override with Socket Basics API config if no explicit JSON config provided
    # API config takes precedence over environment defaults
    if not json_config:
        logger = logging.getLogger(__name__)
        logger.debug(" No JSON config provided, attempting to load Socket Basics API config")
        socket_basics_config = load_socket_basics_config()
        logger.debug(f" Socket Basics API config result: {socket_basics_config is not None}")
        if socket_basics_config:
            # Normalize camelCase API keys to snake_case internal format
            normalized_config = normalize_api_config(socket_basics_config)
            # Filter out empty strings for rule configs - treat them as unset to use code defaults
            # Only filter string values ending with _enabled_rules or _disabled_rules
            filtered_config = {}
            for k, v in normalized_config.items():
                if isinstance(v, str) and v == '' and (k.endswith('_enabled_rules') or k.endswith('_disabled_rules')):
                    # Skip empty rule config strings - they'll fall back to defaults
                    logger.debug(f"Filtering out empty rule config: {k}")
                    continue
                filtered_config[k] = v
            config.update(filtered_config)
            logging.getLogger(__name__).info("Loaded Socket Basics API configuration (overrides environment defaults)")
        else:
            logger.debug(" No Socket Basics API config loaded")
    
    # Override with explicit JSON config if provided
    # JSON config also takes precedence over environment defaults
    if json_config:
        # Also normalize JSON config in case it comes from API
        normalized_json = normalize_api_config(json_config)
        # Filter out empty strings for rule configs - treat them as unset to use code defaults
        filtered_json = {}
        for k, v in normalized_json.items():
            if isinstance(v, str) and v == '' and (k.endswith('_enabled_rules') or k.endswith('_disabled_rules')):
                # Skip empty rule config strings - they'll fall back to defaults
                logger.debug(f"Filtering out empty rule config: {k}")
                continue
            filtered_json[k] = v
        config.update(filtered_json)
        logging.getLogger(__name__).info("Loaded JSON configuration (overrides environment defaults)")
    
    # Note: CLI arguments are handled separately and take highest priority
    # They override the config object after this merge completes
    
    return config


def load_connectors_config() -> Dict[str, Any]:
    """Load connectors configuration from YAML file"""
    try:
        base_dir = Path(__file__).parent.parent  # Go up from core to socket_basics
        config_path = base_dir / "connectors.yaml"
        
        if not config_path.exists():
            return {}
            
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.getLogger(__name__).warning("Warning: Could not load connectors config: %s", e)
        return {}


def add_dynamic_cli_args(parser: argparse.ArgumentParser):
    """Add CLI arguments based on connectors configuration"""
    try:
        connectors_config = load_connectors_config()
        
        for connector_name, connector_config in connectors_config.get('connectors', {}).items():
            for param in connector_config.get('parameters', []):
                option = param.get('option')
                if not option:
                    continue
                    
                param_type = param.get('type', 'str')
                description = param.get('description', f"Enable {connector_name}")
                default = param.get('default')
                
                if param_type == 'bool':
                    parser.add_argument(option, action='store_true', help=description)
                elif param_type == 'str':
                    parser.add_argument(option, type=str, default=default, help=description)
                elif param_type == 'int':
                    parser.add_argument(option, type=int, default=default, help=description)
                    
    except Exception as e:
        logging.getLogger(__name__).warning("Warning: Could not load dynamic CLI args: %s", e)

    # Add optional changed-files CLI argument to limit scans to changed files
    parser.add_argument('--changed-files', type=str, default='',
                        help="Comma-separated list of files to scan or 'auto' to detect changed files from git")

    # Also add CLI args for notification plugins declared in notifications.yaml
    try:
        base_dir = Path(__file__).parent.parent
        notif_path = base_dir / 'notifications.yaml'
        if notif_path.exists():
            with open(notif_path, 'r') as f:
                notif_cfg = yaml.safe_load(f) or {}
            for n_name, n_cfg in (notif_cfg.get('notifiers') or {}).items():
                for param in n_cfg.get('parameters', []) or []:
                    option = param.get('option')
                    p_type = param.get('type', 'str')
                    desc = param.get('description', f"Notification parameter for {n_name}")
                    default = param.get('default')
                    if not option:
                        continue
                    if p_type == 'bool':
                        parser.add_argument(option, action='store_true', help=desc)
                    elif p_type == 'int':
                        parser.add_argument(option, type=int, default=default, help=desc)
                    else:
                        parser.add_argument(option, type=str, default=default, help=desc)
    except Exception:
        pass


def parse_cli_args():
    """Parse command line arguments and return argument parser"""
    parser = argparse.ArgumentParser(description='Socket Security Basics - Dynamic security scanning')
    parser.add_argument('--config', type=str, 
                       help='Path to JSON configuration file. JSON config is merged with environment variables (environment takes precedence)')
    parser.add_argument('--output', type=str, default='.socket.facts.json', 
                       help='Output file name (default: .socket.facts.json)')
    parser.add_argument('--workspace', type=str, help='Workspace directory to scan')
    parser.add_argument('--repo', type=str, help='Repository name (use when workspace is not a git repo)')
    parser.add_argument('--branch', type=str, help='Branch name (use when workspace is not a git repo)')
    parser.add_argument('--default-branch', action='store_true', help='Explicitly mark this as the default branch (sets make_default_branch=true and set_as_pending_head=true)')
    parser.add_argument('--commit-message', type=str, help='Commit message for full scan submission')
    parser.add_argument('--pull-request', type=int, help='Pull request number for full scan submission')
    parser.add_argument('--committers', type=str, help='Comma-separated list of committers for full scan submission')
    parser.add_argument('--scan-files', type=str, help='Comma-separated list of files to scan')
    parser.add_argument('--console-tabular-enabled', action='store_true', help='Enable consolidated console tabular output')
    parser.add_argument('--console-json-enabled', action='store_true', help='Enable consolidated console JSON output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    parser.add_argument('--enable-s3-upload', action='store_true', help='Enable uploading the output file to S3 using SOCKET_S3_* env vars')
    
    # Add dynamic CLI arguments from connectors configuration
    add_dynamic_cli_args(parser)
    
    return parser


def create_config_from_args(args) -> Config:
    """Create configuration object from parsed CLI arguments"""
    # Load base config from environment or JSON file
    if args.config:
        try:
            json_config = load_config_from_json(args.config)
            config_dict = merge_json_and_env_config(json_config)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            logger = logging.getLogger(__name__)
            logger.error("Failed to load JSON config from %s: %s", args.config, e)
            raise SystemExit(f"Error loading configuration file: {e}")
    else:
        config_dict = merge_json_and_env_config()
    
    # Override config with CLI args
    if args.workspace:
        config_dict['workspace'] = args.workspace
        # When workspace is explicitly set, default output_dir to workspace unless OUTPUT_DIR env var is set
        if 'OUTPUT_DIR' not in os.environ:
            config_dict['output_dir'] = args.workspace
    if args.scan_files:
        config_dict['scan_files'] = args.scan_files
    # Console tabular flag (new) with fallback to deprecated name
    if getattr(args, 'console_tabular_enabled', False) or getattr(args, 'output_console_enabled', False):
        config_dict['console_tabular_enabled'] = True

    # Console JSON flag (new) with fallback to deprecated name
    if getattr(args, 'console_json_enabled', False) or getattr(args, 'output_json_enabled', False):
        config_dict['console_json_enabled'] = True
    if args.verbose:
        config_dict['verbose'] = args.verbose
        # Repository/branch discovery with precedence: CLI -> Env -> Git -> Error
    config_dict['repo'] = _discover_repository(
        getattr(args, 'repo', None),
        github_repository=config_dict.get('github_repository', ''),
        github_event_path=config_dict.get('github_event_path', '')
    )
    config_dict['branch'] = _discover_branch(
        getattr(args, 'branch', None),
        github_head_ref=config_dict.get('github_head_ref', ''),
        github_ref_name=config_dict.get('github_ref_name', ''),
        github_event_path=config_dict.get('github_event_path', '')
    )
    config_dict['commit_hash'] = _discover_commit_hash()
    
    # Default branch detection: CLI flag -> Environment -> Git detection
    is_default_branch = False
    if getattr(args, 'default_branch', False):
        # Explicitly set via CLI
        is_default_branch = True
        logger = logging.getLogger(__name__)
        logger.debug("Default branch explicitly set via --default-branch CLI flag")
    elif config_dict.get('socket_default_branch', False):
        # Set via SOCKET_DEFAULT_BRANCH environment variable
        is_default_branch = True
        logger = logging.getLogger(__name__)
        logger.debug("Default branch set via SOCKET_DEFAULT_BRANCH environment variable")
    else:
        # Auto-detect by comparing current branch with repository default
        current_branch = config_dict.get('branch', '')
        workspace_path = config_dict.get('workspace', '')
        is_default_branch = _discover_is_default_branch(current_branch, workspace_path)
    
    config_dict['is_default_branch'] = is_default_branch
    
    # Handle additional full scan parameters
    if getattr(args, 'commit_message', None):
        config_dict['commit_message'] = args.commit_message
    
    # Pull request discovery: CLI -> Environment -> Default to 0
    if getattr(args, 'pull_request', None) is not None:
        config_dict['pull_request'] = args.pull_request
    else:
        config_dict['pull_request'] = _discover_pull_request(
            github_pr_number=config_dict.get('github_pr_number', ''),
            github_event_path=config_dict.get('github_event_path', ''),
            github_head_ref=config_dict.get('github_head_ref', '')
        )
    
    # Committer discovery: CLI -> Git -> Environment
    if getattr(args, 'committers', None):
        # Parse comma-separated committers from CLI
        committers = [c.strip() for c in args.committers.split(',') if c.strip()]
        config_dict['committers'] = committers
    else:
        # Auto-discover committers from git
        config_dict['committers'] = _discover_committers(
            github_actor=config_dict.get('github_actor', '')
        )
        
    if getattr(args, 'enable_s3_upload', False):
        config_dict['enable_s3_upload'] = True
    else:
        # Allow enabling S3 uploads via environment variable SOCKET_S3_ENABLED
        # so sourcing an .env file with SOCKET_S3_ENABLED=true will trigger uploads
        if os.getenv('SOCKET_S3_ENABLED', '').lower() in ('true', '1', 'yes'):
            config_dict['enable_s3_upload'] = True
    
    # Dynamically apply connector parameters from CLI args
    try:
        connectors_config = load_connectors_config()
        
        for connector_name, connector_config in connectors_config.get('connectors', {}).items():
            for param in connector_config.get('parameters', []):
                param_name = param.get('name')
                option = param.get('option')
                
                if param_name and option:
                    # Convert option like "--python" to attribute name "python"
                    arg_name = option.lstrip('-').replace('-', '_')
                    
                    if hasattr(args, arg_name):
                        arg_value = getattr(args, arg_name)
                        if arg_value is not None:
                            if param.get('type') == 'bool' and arg_value:
                                config_dict[param_name] = True
                                
                                # Handle enables/disables attributes
                                if 'enables' in param:
                                    for enabled_param in param['enables']:
                                        config_dict[enabled_param] = True
                                        
                                if 'disables' in param:
                                    for disabled_param in param['disables']:
                                        config_dict[disabled_param] = False
                                        
                            elif param.get('type') != 'bool':
                                config_dict[param_name] = arg_value
    except Exception as e:
        logging.getLogger(__name__).warning("Warning: Error processing dynamic CLI args: %s", e)
    
    # Auto-enable scanning when values are provided (removes need for separate enabled flags)
    # If container_images has a value, enable image scanning
    if config_dict.get('container_images'):
        config_dict['trivy_image_enabled'] = True
        config_dict['container_image_scanning_enabled'] = True
        logging.getLogger(__name__).debug("Auto-enabled Trivy image scanning because --images provided")
    
    # If dockerfiles has a value, enable Dockerfile scanning
    if config_dict.get('dockerfiles'):
        config_dict['trivy_dockerfile_enabled'] = True
        config_dict['dockerfile_scanning_enabled'] = True
        logging.getLogger(__name__).debug("Auto-enabled Trivy Dockerfile scanning because --dockerfiles provided")

    # Persist the chosen output filename into config so connectors can reference it
    try:
        output_arg = getattr(args, 'output', None)
        if output_arg:
            config_dict['output'] = output_arg
    except Exception:
        pass

    # Handle changed-files: CLI overrides env/config. Accept 'auto' to detect via git
    changed_files_arg = getattr(args, 'changed_files', '') if args is not None else ''
    if changed_files_arg:
        val = str(changed_files_arg).strip()
        # 'auto' defaults to staged changes (--cached)
        if val.lower() == 'auto':
            try:
                git_changed = _detect_git_changed_files(config_dict.get('workspace', os.getcwd()), mode='staged')
                config_dict['changed_files'] = git_changed
            except Exception as e:
                logging.getLogger(__name__).warning("Warning: failed to detect git changed files (staged): %s", e)
                config_dict['changed_files'] = []
        elif val.lower() in ('current-commit', 'current_commit'):
            try:
                git_changed = _detect_git_changed_files(config_dict.get('workspace', os.getcwd()), mode='current-commit')
                config_dict['changed_files'] = git_changed
            except Exception as e:
                logging.getLogger(__name__).warning("Warning: failed to detect git changed files (current-commit): %s", e)
                config_dict['changed_files'] = []
        else:
            # If value looks like a commit hash, list files in that commit
            import re
            if re.match(r'^[0-9a-fA-F]{7,40}$', val):
                try:
                    git_changed = _detect_git_changed_files(config_dict.get('workspace', os.getcwd()), mode='commit', commit=val)
                    config_dict['changed_files'] = git_changed
                except Exception as e:
                    logging.getLogger(__name__).warning("Warning: failed to detect git changed files (commit %s): %s", val, e)
                    config_dict['changed_files'] = []
            else:
                # parse comma-separated list of files provided manually
                config_dict['changed_files'] = [f.strip() for f in val.split(',') if f.strip()]
    else:
        # preserve any changed_files provided via env/config
        if 'changed_files' not in config_dict:
            config_dict['changed_files'] = []

    # Post-processing: ensure repository/branch are set; if workspace isn't a git repo,
    # require explicit --repo and --branch to be provided.
    try:
        ws = config_dict.get('workspace', os.getcwd())
        git_dir = Path(ws) / '.git'
        if git_dir.exists():
            try:
                # Detect branch if not already set
                if 'branch' not in config_dict or not config_dict.get('branch'):
                    import subprocess
                    branch_name = subprocess.check_output(['git', '-C', str(ws), 'rev-parse', '--abbrev-ref', 'HEAD']).decode().strip()
                    if branch_name:
                        config_dict.setdefault('branch', branch_name)
            except Exception:
                # ignore git detection failures
                pass
        else:
            # Not a git repo: require CLI-provided repo and branch
            if not config_dict.get('repo') or not config_dict.get('branch'):
                raise RuntimeError('Workspace is not a git repository; please provide --repo and --branch')
    except RuntimeError:
        # propagate to caller so CLI user sees the error
        raise
    except Exception:
        # Non-fatal: continue with whatever repository/branch values we have
        pass

    return Config(config_dict)


def _detect_git_changed_files(workspace_path: str, mode: str = 'staged', commit: str | None = None) -> List[str]:
    """Detect changed files in a git repository.

    mode:
      - 'staged' -> files staged for commit (git diff --name-only --cached)
      - 'current-commit' -> files included in HEAD commit
      - 'commit' -> files included in the given commit hash (commit param required)

    Returns a list of file paths relative to the workspace root. If not a git repo or detection fails, returns [].
    """
    try:
        from subprocess import check_output, CalledProcessError
        import subprocess
        
        # Prefer GITHUB_WORKSPACE if set (GitHub Actions environment)
        # Otherwise use the provided workspace_path
        if os.environ.get('GITHUB_WORKSPACE'):
            ws = Path(os.environ['GITHUB_WORKSPACE'])
        else:
            ws = Path(workspace_path) if workspace_path else Path.cwd()
            
        if not ws.exists():
            return []

        # Ensure this is a git repo
        git_dir = ws / '.git'
        if not git_dir.exists():
            return []

        # Change to workspace directory before running git commands
        # This ensures git runs in the correct repository context
        original_cwd = os.getcwd()
        try:
            os.chdir(str(ws))
            
            if mode == 'staged':
                # staged but not yet committed
                out = check_output(['git', 'diff', '--name-only', '--cached'], text=True, stderr=subprocess.DEVNULL)
            elif mode == 'current-commit':
                # files that are part of HEAD commit
                out = check_output(['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD'], text=True, stderr=subprocess.DEVNULL)
            elif mode == 'commit' and commit:
                out = check_output(['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', commit], text=True, stderr=subprocess.DEVNULL)
            else:
                return []

            files = [line.strip() for line in out.splitlines() if line.strip()]
            return files
        finally:
            # Always restore original working directory
            os.chdir(original_cwd)
            
    except CalledProcessError:
        return []
    except Exception:
        return []


def discover_all_files(workspace_path: str, respect_gitignore: bool = True) -> List[str]:
    """Discover all files in a workspace, optionally respecting .gitignore patterns.
    
    Args:
        workspace_path: Path to the workspace directory
        respect_gitignore: Whether to respect .gitignore patterns (default: True)
        
    Returns:
        List of relative file paths from the workspace root
    """
    import fnmatch
    import os
    
    workspace = Path(workspace_path)
    if not workspace.exists() or not workspace.is_dir():
        return []
    
    all_files = []
    gitignore_patterns = []
    
    # Load .gitignore patterns if requested and file exists
    if respect_gitignore:
        gitignore_file = workspace / '.gitignore'
        if gitignore_file.exists():
            try:
                with open(gitignore_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # Skip empty lines and comments
                        if not line or line.startswith('#'):
                            continue
                        gitignore_patterns.append(line)
            except Exception:
                # If we can't read .gitignore, continue without patterns
                pass
    
    # Always ignore common patterns even if no .gitignore
    default_ignore_patterns = [
        '.git',
        '.git/**',
        '__pycache__',
        '__pycache__/**',
        '*.pyc',
        '.DS_Store',
        '.venv',
        '.venv/**',
        'venv',
        'venv/**',
        'node_modules',
        'node_modules/**',
        '.tmp',
        '.tmp/**',
        'custom_rules',
        'custom_rules/**',
    ]
    
    all_patterns = gitignore_patterns + default_ignore_patterns
    
    def should_ignore(file_path: str) -> bool:
        """Check if a file should be ignored based on patterns"""
        # Convert to forward slashes for consistent pattern matching
        normalized_path = file_path.replace(os.sep, '/')
        
        for pattern in all_patterns:
            # Handle directory patterns (ending with /)
            if pattern.endswith('/'):
                dir_pattern = pattern[:-1]
                if normalized_path == dir_pattern or normalized_path.startswith(dir_pattern + '/'):
                    return True
            # Handle patterns with /** (recursive directory)
            elif '/**' in pattern:
                base_pattern = pattern.replace('/**', '')
                if normalized_path.startswith(base_pattern + '/') or normalized_path == base_pattern:
                    return True
            # Handle glob patterns
            elif '*' in pattern or '?' in pattern:
                if fnmatch.fnmatch(normalized_path, pattern):
                    return True
                # Also check if any parent directory matches
                parts = normalized_path.split('/')
                for i in range(1, len(parts) + 1):
                    partial_path = '/'.join(parts[:i])
                    if fnmatch.fnmatch(partial_path, pattern):
                        return True
            # Handle exact matches
            else:
                if normalized_path == pattern or normalized_path.startswith(pattern + '/'):
                    return True
        
        return False
    
    # Walk the directory tree
    try:
        for root, dirs, files in os.walk(workspace):
            # Get relative path from workspace
            rel_root = os.path.relpath(root, workspace)
            if rel_root == '.':
                rel_root = ''
            
            # Filter out directories that should be ignored
            dirs[:] = [d for d in dirs if not should_ignore(os.path.join(rel_root, d) if rel_root else d)]
            
            # Add files that shouldn't be ignored
            for file in files:
                rel_file_path = os.path.join(rel_root, file) if rel_root else file
                if not should_ignore(rel_file_path):
                    all_files.append(rel_file_path)
    
    except Exception:
        # If directory walking fails, return empty list
        return []
    
    # Sort for consistent ordering
    all_files.sort()
    return all_files


def _parse_github_event(github_event_path: str = '') -> Dict[str, str]:
    """Parse GitHub event.json file for repo and branch information
    
    Args:
        github_event_path: Path to GitHub event file from GITHUB_EVENT_PATH
    
    Returns:
        Dict with 'repo' and 'branch' keys, empty strings if not found
    """
    event_info = {'repo': '', 'branch': ''}
    
    # Only look for event file if we're in a GitHub environment
    if not github_event_path:
        return event_info
    
    # Use the event path from environment, fallback to 'event.json'
    event_file = Path(github_event_path)
    if not event_file.exists():
        return event_info
    
    try:
        with open(event_file, 'r') as f:
            event_data = json.load(f)
        
        # Extract repo from pull_request.head.repo.full_name or repository.full_name
        if 'pull_request' in event_data and 'head' in event_data['pull_request']:
            pr_head = event_data['pull_request']['head']
            if 'repo' in pr_head and 'full_name' in pr_head['repo']:
                event_info['repo'] = pr_head['repo']['full_name']
            # Extract branch from pull_request.head.ref
            if 'ref' in pr_head:
                event_info['branch'] = pr_head['ref']
        elif 'repository' in event_data and 'full_name' in event_data['repository']:
            event_info['repo'] = event_data['repository']['full_name']
            
    except (json.JSONDecodeError, KeyError, Exception) as e:
        logging.getLogger(__name__).debug("Failed to parse event.json: %s", e)
    
    return event_info


def _discover_repository(cli_repo: str | None, github_repository: str = '', github_event_path: str = '') -> str:
    """Discover repository name with precedence: CLI -> SCM Env -> GitHub event.json -> Git -> Error
    
    Args:
        cli_repo: Repository from CLI argument (highest precedence)
        
    Returns:
        Repository name in 'owner/repo' format
        
    Raises:
        SystemExit: If repository cannot be determined
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    
    # 1. CLI Option (highest precedence)
    if cli_repo:
        logger.debug("Using repository from CLI: %s", cli_repo)
        return cli_repo
    
    # 2. SCM Environment Variables (GitHub Actions, etc.)
    if github_repository:
        logger.debug("Using repository from GitHub environment: %s", github_repository)
        return github_repository
    
    # 3. GitHub event.json file
    event_info = _parse_github_event(github_event_path)
    if event_info['repo']:
        logger.debug("Using repository from event.json: %s", event_info['repo'])
        return event_info['repo']
    
    # 4. Git information
    try:
        url = subprocess.check_output(
            ['git', 'config', '--get', 'remote.origin.url'], 
            text=True, 
            stderr=subprocess.DEVNULL
        ).strip()
        
        if url.endswith('.git'):
            url = url[:-4]
            
        if url.startswith('git@'):
            # git@github.com:owner/repo
            repo = url.split(':', 1)[1]
            logger.debug("Using repository from git remote (SSH): %s", repo)
            return repo
        else:
            # https://github.com/owner/repo
            parts = url.rstrip('/').split('/')
            if len(parts) >= 2:
                repo = f"{parts[-2]}/{parts[-1]}"
                logger.debug("Using repository from git remote (HTTPS): %s", repo)
                return repo
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to discover repository from git: %s", e)
    
    # 5. Error if not found
    logger.error("Could not determine repository name. Please provide --repo argument.")
    raise SystemExit("Repository discovery failed. Use --repo owner/repo to specify manually.")


def _discover_branch(cli_branch: str | None, github_head_ref: str = '', github_ref_name: str = '', github_event_path: str = '') -> str:
    """Discover branch name with precedence: CLI -> SCM Env -> GitHub event.json -> Git -> Error
    
    Args:
        cli_branch: Branch from CLI argument (highest precedence)
        
    Returns:
        Branch name
        
    Raises:
        SystemExit: If branch cannot be determined
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    
    # 1. CLI Option (highest precedence)
    if cli_branch:
        logger.debug("Using branch from CLI: %s", cli_branch)
        return cli_branch
    
    # 2. SCM Environment Variables (GitHub Actions, etc.)
    # For PRs, GITHUB_HEAD_REF contains the PR source branch
    if github_head_ref:
        logger.debug("Using branch from GITHUB_HEAD_REF: %s", github_head_ref)
        return github_head_ref
    
    # For direct pushes, GITHUB_REF_NAME contains the branch
    if github_ref_name:
        logger.debug("Using branch from GITHUB_REF_NAME: %s", github_ref_name)
        return github_ref_name
    
    # 3. GitHub event.json file
    event_info = _parse_github_event(github_event_path)
    if event_info['branch']:
        logger.debug("Using branch from event.json: %s", event_info['branch'])
        return event_info['branch']
    
    # 4. Git information
    try:
        branch = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
        
        if branch and branch != 'HEAD':
            logger.debug("Using branch from git: %s", branch)
            return branch
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to discover branch from git: %s", e)
    
    # 5. Error if not found (if not a git repo and still unknown)
    logger.error("Could not determine branch name. Please provide --branch argument.")
    raise SystemExit("Branch discovery failed. Use --branch branch-name to specify manually.")


def _discover_commit_hash() -> str:
    """Discover current commit hash from git
    
    Returns:
        Commit hash (short form) or empty string if not available
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    
    # 1. Environment Variable (GitHub Actions)
    commit = os.getenv('GITHUB_SHA')
    if commit:
        # Return short form (first 7 characters)
        short_commit = commit[:7] if len(commit) >= 7 else commit
        logger.debug("Using commit hash from environment: %s", short_commit)
        return short_commit
    
    # 2. Git information
    try:
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'], 
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
        
        if commit:
            logger.debug("Using commit hash from git: %s", commit)
            return commit
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to discover commit hash from git: %s", e)
    
    # 3. Return empty string if not found (commit hash is optional)
    logger.debug("Could not determine commit hash - this is optional")
    return ""


def _discover_is_default_branch(current_branch: str, workspace_path: str = '') -> bool:
    """Discover if the current branch is the default branch for the repository
    
    Args:
        current_branch: The current branch name
        workspace_path: The workspace directory path (defaults to current directory)
    
    Returns:
        True if current branch is the default branch, False otherwise
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    
    if not current_branch:
        logger.debug("No current branch provided, cannot determine if it's default")
        return False
    
    # 1. Try to get the default branch from git remote (most reliable)
    try:
        # Change to the workspace directory for git commands
        cwd = workspace_path if workspace_path else None
        
        # Get the default branch from the remote origin
        result = subprocess.check_output(
            ['git', 'symbolic-ref', 'refs/remotes/origin/HEAD'],
            text=True,
            stderr=subprocess.DEVNULL,
            cwd=cwd
        ).strip()
        
        # Extract branch name from refs/remotes/origin/branch-name
        if result and result.startswith('refs/remotes/origin/'):
            default_branch = result.replace('refs/remotes/origin/', '')
            is_default = current_branch == default_branch
            logger.debug("Default branch from git remote: %s, current: %s, is_default: %s", 
                        default_branch, current_branch, is_default)
            return is_default
            
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to get default branch from git remote: %s", e)
    
    # 2. Fallback: try to get default branch via git ls-remote
    try:
        # Get the default branch by checking what HEAD points to on the remote
        result = subprocess.check_output(
            ['git', 'ls-remote', '--symref', 'origin', 'HEAD'],
            text=True,
            stderr=subprocess.DEVNULL,
            cwd=cwd
        ).strip()
        
        # Parse the output: "ref: refs/heads/main\tHEAD"
        for line in result.split('\n'):
            if line.startswith('ref: refs/heads/'):
                default_branch = line.split('ref: refs/heads/')[1].split('\t')[0]
                is_default = current_branch == default_branch
                logger.debug("Default branch from ls-remote: %s, current: %s, is_default: %s", 
                            default_branch, current_branch, is_default)
                return is_default
                
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to get default branch from ls-remote: %s", e)
    
    # 3. Fallback: check common default branch names
    common_defaults = ['main', 'master', 'develop', 'trunk']
    if current_branch in common_defaults:
        logger.debug("Current branch '%s' matches common default branch pattern", current_branch)
        return True
    
    # 4. Final fallback: not a default branch
    logger.debug("Could not determine if '%s' is the default branch, assuming it's not", current_branch)
    return False


def _discover_pull_request(github_pr_number: str = '', github_event_path: str = '', github_head_ref: str = '') -> int:
    """Discover pull request number from environment
    
    Args:
        github_pr_number: GITHUB_PR_NUMBER environment variable
        github_event_path: GITHUB_EVENT_PATH environment variable  
        github_head_ref: GITHUB_HEAD_REF environment variable
    
    Returns:
        Pull request number or 0 if not found/not a PR
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    
    # 1. Environment Variable (GitHub Actions)
    if github_pr_number:
        try:
            pr_num = int(github_pr_number)
            logger.debug("Using PR number from GITHUB_PR_NUMBER: %s", pr_num)
            return pr_num
        except ValueError:
            logger.debug("Invalid PR number in GITHUB_PR_NUMBER: %s", github_pr_number)
    
    # 2. GitHub event.json file (only if in GitHub environment)
    if github_event_path:
        event_file = Path(github_event_path)
        if event_file.exists():
            try:
                with open(event_file, 'r') as f:
                    event_data = json.load(f)
                
                # Extract PR number from pull_request.number
                if 'pull_request' in event_data and 'number' in event_data['pull_request']:
                    pr_num = event_data['pull_request']['number']
                    logger.debug("Using PR number from event.json: %s", pr_num)
                    return pr_num
            except (json.JSONDecodeError, KeyError, Exception) as e:
                logger.debug("Failed to parse PR number from event.json: %s", e)
    
    # 3. Check if we're in a GitHub PR context
    if github_head_ref:
        # We're in a PR context but don't have the number
        logger.debug("In GitHub PR context but no PR number found, defaulting to 0")
        return 0
    
    # 4. Not a PR context
    logger.debug("Not in a PR context, returning 0")
    return 0


def _discover_committers(github_actor: str = '') -> List[str]:
    """Discover committer emails from git with GitHub user ID preference
    
    Args:
        github_actor: GITHUB_ACTOR environment variable
    
    Returns:
        List of committer email addresses, preferring GitHub user IDs when available
    """
    import subprocess
    
    logger = logging.getLogger(__name__)
    committers = []
    
    # 1. Environment Variables (GitHub Actions) - prefer GitHub user ID
    if github_actor:
        # Use the GitHub username directly as the committer
        committers.append(github_actor)
        logger.debug("Using GitHub user ID from GITHUB_ACTOR: %s", github_actor)
        return committers  # Return early since we have the preferred GitHub user ID
    
    # 2. Git information - get the current commit author email
    git_email = None
    try:
        git_email = subprocess.check_output(
            ['git', 'log', '-1', '--pretty=format:%ae'], 
            text=True,
            stderr=subprocess.DEVNULL
        ).strip()
        
        if git_email:
            logger.debug("Found git commit author email: %s", git_email)
    except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
        logger.debug("Failed to discover committer email from git: %s", e)
    
    # 3. Git config user.email as fallback
    if not git_email:
        try:
            git_email = subprocess.check_output(
                ['git', 'config', 'user.email'], 
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
            
            if git_email:
                logger.debug("Found git config user.email: %s", git_email)
        except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
            logger.debug("Failed to discover committer email from git config: %s", e)
    
    # 4. Extract GitHub user ID from email if it's a GitHub noreply email
    if git_email:
        # Check if it's a GitHub noreply email pattern: username@users.noreply.github.com
        if git_email.endswith('@users.noreply.github.com'):
            github_username = git_email.split('@')[0]
            committers.append(github_username)
            logger.debug("Extracted GitHub user ID from noreply email: %s", github_username)
        else:
            # Use the configured email as-is
            committers.append(git_email)
            logger.debug("Using configured email: %s", git_email)
    
    # 5. Return empty list if no committers found
    if not committers:
        logger.debug("Could not determine committer information")
    
    return committers
