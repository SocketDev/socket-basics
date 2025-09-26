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
from typing import Dict, Any, List


class Config:
    """Configuration object that provides unified access to all settings"""
    
    def __init__(self, config_dict: Dict[str, Any] = None):
        """Initialize configuration from dictionary or environment"""
        if config_dict is None:
            config_dict = load_config_from_env()
        
        self._config = config_dict
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
        
        if not rules_str.strip():
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


def load_config_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables dynamically from connectors.yaml"""
    config = {
        # Core workspace settings
        'workspace': os.getenv('GITHUB_WORKSPACE', os.getcwd()),
        'output_dir': os.getenv('OUTPUT_DIR', os.getcwd()),
        
        # Scan scope
        'scan_all': os.getenv('INPUT_SCAN_ALL', 'false').lower() == 'true',
        'scan_files': os.getenv('INPUT_SCAN_FILES', ''),
        
        # OpenGrep configuration (optional override for custom rules)
        'opengrep_rules_dir': os.getenv('INPUT_OPENGREP_RULES_DIR', ''),
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
    parser.add_argument('--config', type=str, help='JSON config file path')
    parser.add_argument('--output', type=str, default='.socket.facts.json', 
                       help='Output file name (default: .socket.facts.json)')
    parser.add_argument('--workspace', type=str, help='Workspace directory to scan')
    parser.add_argument('--repo', type=str, help='Repository name (use when workspace is not a git repo)')
    parser.add_argument('--branch', type=str, help='Branch name (use when workspace is not a git repo)')
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
        with open(args.config, 'r') as f:
            config_dict = json.load(f)
    else:
        config_dict = load_config_from_env()
    
    # Override config with CLI args
    if args.workspace:
        config_dict['workspace'] = args.workspace
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
    # Repository/branch overrides from CLI
    if getattr(args, 'repo', None):
        config_dict['repository'] = args.repo
    if getattr(args, 'branch', None):
        config_dict['branch'] = args.branch
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
            if not config_dict.get('repository') or not config_dict.get('branch'):
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
        ws = Path(workspace_path)
        if not ws.exists():
            return []

        # Ensure this is a git repo
        git_dir = ws / '.git'
        if not git_dir.exists():
            return []

        if mode == 'staged':
            # staged but not yet committed
            out = check_output(['git', '-C', str(ws), 'diff', '--name-only', '--cached'], text=True)
        elif mode == 'current-commit':
            # files that are part of HEAD commit
            out = check_output(['git', '-C', str(ws), 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD'], text=True)
        elif mode == 'commit' and commit:
            out = check_output(['git', '-C', str(ws), 'diff-tree', '--no-commit-id', '--name-only', '-r', commit], text=True)
        else:
            return []

        files = [line.strip() for line in out.splitlines() if line.strip()]
        return files
    except CalledProcessError:
        return []
    except Exception:
        return []
