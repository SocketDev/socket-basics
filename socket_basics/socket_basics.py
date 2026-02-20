#!/usr/bin/env python3
"""
Socket Security Basics - A fresh start for security scanning with dynamic connectors
"""

import sys
# Require Python 3.10+ for PEP 604 union types and other modern syntax used in this codebase.
if sys.version_info < (3, 10):
    raise RuntimeError(
        f"Socket Basics requires Python >= 3.10 but the current interpreter is {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}.\n"
        "Please recreate the virtualenv with a suitable Python (eg. Homebrew python@3.10 or python@3.13) and reinstall dependencies.\n"
        "Example:\n  brew install python@3.10\n  python3.10 -m venv .venv && source .venv/bin/activate && pip install -e .\n"
    )

import json
import logging
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib
try:
    # Python 3.11+
    import tomllib
except ModuleNotFoundError:
    # Backport for older Python versions — provided as a conditional dep in pyproject.toml
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        # Leave a clear error when tomllib/tomli not available at runtime
        tomllib = None
from copy import deepcopy

# Import package version; connectors and notifiers can import from here
try:
    from .version import __version__
except Exception:
    # fallback to empty string if version module isn't available
    __version__ = ''

# Import the new modular components
try:
    # Relative imports for when used as a package
    from .core.config import Config, parse_cli_args, create_config_from_args
    from .core.connector import ConnectorManager
    from .core.notification.manager import NotificationManager
except ImportError:
    # Absolute imports for when run as a script (best-effort fallback)
    from socket_basics.core.config import Config, parse_cli_args, create_config_from_args
    from socket_basics.core.connector import ConnectorManager
    from socket_basics.core.notification.manager import NotificationManager

# Configure logger (basicConfig will be applied in main)
logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanning orchestrator using dynamic connectors"""

    def __init__(self, config: Config):
        self.config = config

        # Initialize connector manager for dynamic loading
        self.connector_manager = ConnectorManager(config)
        # Initialize notification manager (config loaded later)
        self.notification_manager = None
        # Expose version from version.py to config immediately
        try:
            setattr(self.config, 'socket_basics_version', __version__)
        except Exception:
            pass
    
    def run_all_scans(self) -> Dict[str, Any]:
        """Run all enabled security scans using dynamic connector loading"""
        logger.info("Starting security scanning with dynamic connectors...")
        
        # Use the connector manager to run all scans. Expect the canonical
        # return shape: {'components': [...], 'notifications': [...]}
    # Call connector manager which returns {'components': [...], 'notifications': [...]}
        scan_return = self.connector_manager.run_all_scans()

        if not isinstance(scan_return, dict):
            logger.error("ConnectorManager returned non-dict result; got: %s", type(scan_return))
            raise RuntimeError("ConnectorManager did not return the expected dict result from run_all_scans()")

        components = scan_return.get('components') or []
        notifications = scan_return.get('notifications') or []

    # Flatten wrapper components that include a 'data' list
        expanded_components = []
        for comp in components:
            if isinstance(comp, dict) and isinstance(comp.get('data'), list):
                data_list = comp.get('data') or []
                for inner in data_list:
                    try:
                        ic = deepcopy(inner)
                    except Exception:
                        ic = inner
                    expanded_components.append(ic)
            else:
                expanded_components.append(comp)

        final_results = {"components": expanded_components}
        try:
            if notifications:
                final_results['notifications'] = notifications
        except Exception:
            pass

        return final_results
    
    def save_results(self, results: Dict[str, Any], filename: str = '.socket.facts.json'):
        """Save results to a Socket facts JSON file"""
        output_path = Path(self.config.output_dir) / filename
        tmp_path = output_path.with_name(output_path.name + '.tmp')

        # Ensure parent directory exists
        if output_path.parent and not output_path.parent.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)

        mem_components = results.get('components', []) or []

        final_components: list = []
        if mem_components:
            for c in mem_components:
                # If connector returned a wrapper containing 'data', expand and
                # append inner components verbatim. Do not append the wrapper
                # itself so connectors control what appears in the final list.
                if isinstance(c, dict) and isinstance(c.get('data'), list):
                    data_list = c.get('data') or []
                    for inner in data_list:
                        try:
                            ic = deepcopy(inner)
                        except Exception:
                            ic = inner
                        final_components.append(ic)
                else:
                    final_components.append(c)
        else:
            # No in-memory components: try to preserve existing tmp file if present
            try:
                if tmp_path.exists():
                    with open(tmp_path, 'r', encoding='utf-8') as tf:
                        tmp_data = json.load(tf) or {}
                        final_components = tmp_data.get('components', []) or []
            except Exception:
                logger.debug('Failed to read existing tmp output; proceeding with empty components')

        final_results = {'components': final_components}
    # qualifiers coercion removed: connectors should provide serializable
    # values for any optional fields. No automatic coercion is performed.
        # Ensure components are dicts; leave field normalization to earlier pass
        # Do not perform legacy normalization on components when saving results.
        # Components should already contain a `scanners` list (set by connectors or aggregated
        # during normalization in run_all_scans). We preserve components verbatim here.

        # Write final results to tmp and atomically move into place
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        try:
            os.replace(str(tmp_path), str(output_path))
        except Exception:
            tmp_path.rename(output_path)

        logger.info(f"Results saved to: {output_path}")
        return output_path

    def load_notification_manager(self, notifications_cfg: Dict[str, Any] | None = None):
        """Create and load NotificationManager from YAML/config dict or default file.

        notifications_cfg: optional dict already loaded from notifications.yaml
        """
        cfg = notifications_cfg
        if cfg is None:
            try:
                base_dir = Path(__file__).parent
                cfg_path = base_dir / "notifications.yaml"
                if cfg_path.exists():
                    try:
                        import yaml
                    except Exception:
                        yaml = None
                    if yaml is not None:
                        with open(cfg_path, 'r') as f:
                            cfg = yaml.safe_load(f)
            except Exception:
                cfg = None

        # pass the active config dict to NotificationManager so it can consult connector preferences
        nm = NotificationManager(cfg, app_config=self.config._config)
        nm.load_from_config()
        self.notification_manager = nm

    def submit_socket_facts(self, socket_facts_path: Path, results: Dict[str, Any]) -> Dict[str, Any]:
        """Submit the socket facts file to Socket API and return full scan results.

        Args:
            socket_facts_path: Path to the .socket.facts.json file
            results: Current scan results dict to update with full scan info

        Returns:
            Updated results dict with full scan information (id, html_url)
        """
        # Check if Socket submission should be skipped (for Node.js Socket CLI integration).
        # When SKIP_SOCKET_SUBMISSION=1, socket-basics generates the .socket.facts.json
        # file but does not submit it to the Socket API. This allows the Node.js Socket CLI to
        # collect the facts and submit them in a unified API call along with manifest data.
        if os.getenv('SKIP_SOCKET_SUBMISSION') == '1':
            logger.info("Skipping Socket API submission (SKIP_SOCKET_SUBMISSION=1)")
            logger.debug(f"Socket facts file will be available at: {socket_facts_path}")
            # Include the facts file path in results for downstream tools.
            results['socket_facts_path'] = str(socket_facts_path)
            return results

        try:
            # Check if socket facts file is empty or has no components
            if not socket_facts_path.exists():
                logger.debug("Socket facts file does not exist, skipping submission")
                return results
                
            with open(socket_facts_path, 'r') as f:
                facts_data = json.load(f)
                
            components = facts_data.get('components', [])
            if not components:
                logger.debug("Socket facts file is empty (no components), skipping submission")
                return results
                
            # Check if we have the required Socket API configuration
            socket_api_key = self.config.get('socket_api_key')
            if not socket_api_key:
                logger.debug("No Socket API key configured, skipping full scan submission")
                return results
                
            socket_org = self.config.get('socket_org')
            if not socket_org:
                logger.warning(
                    "No Socket organization configured - scan results will not be uploaded to the dashboard. "
                    "This typically means your API key is missing the 'socket-basics:read' scope. "
                    "Please create an API key with the required scopes in Settings > API Tokens "
                    "in the Socket dashboard (https://socket.dev)."
                )
                return results
                
            # Import socketdev SDK
            try:
                logger.debug("Importing socketdev SDK")
                from socketdev import socketdev
                from socketdev.fullscans import FullScanParams
                logger.debug("✓ socketdev SDK imported successfully")
            except ImportError as e:
                logger.warning(f"Failed to import socketdev SDK: {e}")
                return results
                
            # Initialize SDK
            logger.debug("Initializing socketdev SDK")
            sdk = socketdev(token=socket_api_key, timeout=100)
            logger.debug("✓ socketdev SDK initialized")
            
            # Prepare full scan parameters with proper defaults
            repo_name = self.config.get('repo') or 'socket-basics-scan'
            # Extract just the repo name if it contains org/repo format
            if '/' in repo_name:
                repo_name = repo_name.split('/')[-1]
            
            branch = self.config.get('branch') or 'main'
            commit_hash = self.config.get('commit_hash') or ''
            commit_message = self.config.get('commit_message') or 'Socket Basics security scan'
            pull_request = self.config.get('pull_request')
            committers = self.config.get('committers') or []
            
            logger.debug(f"Creating FullScanParams with: org_slug={socket_org}, repo={repo_name}, branch={branch}")
            
            # Determine if this is the default branch
            is_default_branch = self.config.is_default_branch
            logger.debug(f"Is default branch: {is_default_branch}")
            
            try:
                # Only include pull_request and committers if they have values
                params_dict = {
                    'org_slug': socket_org,
                    'repo': repo_name,
                    'branch': branch,
                    'commit_message': commit_message,
                    'commit_hash': commit_hash,
                    'make_default_branch': is_default_branch,
                    'set_as_pending_head': is_default_branch,
                    'integration_type': "api",
                    'scan_type': "socket_basics"
                }
                
                # Always include pull_request (0 if not a PR)
                pull_request_num = pull_request if pull_request is not None else 0
                params_dict['pull_request'] = pull_request_num
                    
                # Only add committers if there are any
                if committers:
                    params_dict['committers'] = committers
                
                params = FullScanParams(**params_dict)
                logger.debug(f"✓ FullScanParams created successfully")
            except Exception as e:
                logger.error(f"Failed to create FullScanParams: {type(e).__name__}: {str(e)}")
                raise
            
            # Submit the socket facts file
            logger.info(f"Submitting socket facts file to Socket API for organization: {socket_org}")
            logger.debug(f"Full scan parameters: repo={repo_name}, branch={branch}, commit_hash={commit_hash}")
            
            # The SDK needs:
            # 1. Absolute path to the file (so it can be opened)
            # 2. base_path that the file path starts with (so it can be stripped for the upload key)
            socket_facts_absolute = str(socket_facts_path.absolute())
            workspace_absolute = str(Path(self.config.workspace).absolute())
            
            logger.debug(f"Socket facts absolute path: {socket_facts_absolute}")
            logger.debug(f"Workspace absolute path: {workspace_absolute}")
            logger.debug(f"File exists: {socket_facts_path.exists()}")
            logger.debug(f"File starts with workspace: {socket_facts_absolute.startswith(workspace_absolute)}")
            
            try:
                res = sdk.fullscans.post(
                    [socket_facts_absolute],
                    params=params,
                    use_types=True,
                    use_lazy_loading=True,
                    max_open_files=50,
                    base_path=workspace_absolute
                )
                logger.debug(f"✓ SDK call completed")
                logger.debug(f"SDK response type: {type(res)}")
                logger.debug(f"SDK response: {res}")
            except Exception as e:
                logger.error(f"Failed during SDK fullscans.post call: {type(e).__name__}: {str(e)}")
                raise
            
            # SDK typically returns a dict-like response
            if isinstance(res, dict):
                logger.debug("Processing dict-type response")
                # Check for errors in dict response
                if 'error' in res or res.get('success') == False:
                    error_msg = res.get('error', res.get('message', 'Unknown error'))
                    logger.error(f"Error creating full scan: {error_msg}")
                    raise Exception(f"Error creating full scan: {error_msg}")
                    
                # Extract the scan ID and HTML URL from the response
                scan_id = res.get('id')
                html_url = res.get('html_url')
                logger.debug(f"Extracted from dict: scan_id={scan_id}, html_url={html_url}")
            else:
                logger.debug("Processing object-type response")
                # Handle object-based response (if the SDK uses objects)
                if hasattr(res, 'error') or (hasattr(res, 'success') and not res.success):
                    error_msg = getattr(res, 'error', getattr(res, 'message', 'Unknown error'))
                    logger.error(f"Error creating full scan: {error_msg}")
                    raise Exception(f"Error creating full scan: {error_msg}")
                    
                # Extract the scan ID and HTML URL from the response
                scan_id = getattr(res, 'id', None)
                html_url = getattr(res, 'html_url', None)
                logger.debug(f"Extracted from object: scan_id={scan_id}, html_url={html_url}")
                
            if scan_id:
                logger.info(f"Full scan created successfully with ID: {scan_id}")
                results['full_scan_id'] = scan_id
                
            if html_url:
                logger.info(f"Full scan available at: {html_url}")
                results['full_scan_html_url'] = html_url
                
            return results
            
        except Exception as e:
            logger.error(f"Failed to submit socket facts file: {type(e).__name__}: {str(e)}")
            logger.debug("Full traceback:", exc_info=True)
            # Return original results if submission fails
            return results


def main():
    """Main entry point"""
    parser = parse_cli_args()
    args = parser.parse_args()
    # Configure basic logging here so importing the package doesn't
    # mutate global logging configuration unexpectedly.
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )
    # Initialize/rotate the output file immediately so the container run always
    # produces a predictable `.socket.facts.json` file even if scans fail later.
    try:
        out_arg = getattr(args, 'output', '.socket.facts.json') or '.socket.facts.json'
        out_path = Path(out_arg)
        
        # If output path is relative and workspace is specified, make it relative to workspace
        if not out_path.is_absolute() and hasattr(args, 'workspace') and args.workspace:
            workspace_path = Path(args.workspace)
            out_path = workspace_path / out_path
        
        # If file exists, remove it to ensure fresh start
        if out_path.exists():
            out_path.unlink()
        # Ensure parent directory exists
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        # Create an initial empty socket facts file
        with open(out_path, 'w') as f:
            json.dump({"components": []}, f, indent=2)
        logger.info(f"Initialized output file at {out_path}")
    except Exception as _e:
        logger.warning(f"Failed to initialize output file: {_e}")

    
    # Create configuration from CLI args
    config = create_config_from_args(args)
    
    # Create scanner and run
    scanner = SecurityScanner(config)
    results = scanner.run_all_scans()
    
    # Save results
    output_path = scanner.save_results(results, args.output)

    # Submit socket facts file to Socket API if not empty
    try:
        results = scanner.submit_socket_facts(output_path, results)
    except Exception:
        logger.exception("Failed to submit socket facts file")

    # Optionally upload to S3 if requested
    try:
        enable_s3 = getattr(args, 'enable_s3_upload', False) or config.get('enable_s3_upload', False)
        if enable_s3:
            try:
                # Use the helper under socket_basics.plugins.s3 (avoids importing from src/)
                from socket_basics.plugins.s3 import upload_output_file as _upload_output_file
                output_file_path = str(output_path)
                upload_success = _upload_output_file(output_file_path, workspace_path=str(config.workspace) if hasattr(config, 'workspace') else '.')
                if upload_success:
                    logger.info("S3 upload completed")
                else:
                    logger.warning("S3 upload failed or was skipped")
            except Exception:
                logger.exception('Failed to import or run s3 uploader helper')
    except Exception:
        logger.exception("Failed to run S3 upload")
    
    # Print summary
    total_components = len(results.get('components', []))
    total_alerts = sum(len(comp.get('alerts', [])) for comp in results.get('components', []))
    
    logger.info(f"Scan completed!")
    logger.info(f"Components analyzed: {total_components}")
    logger.info(f"Total alerts: {total_alerts}")
    
    # Exit with non-zero code if high/critical issues found
    high_critical_alerts = 0
    for comp in results.get('components', []):
        for alert in comp.get('alerts', []):
            if alert.get('severity') in ['high', 'critical']:
                high_critical_alerts += 1
    
    exit_code = 1 if high_critical_alerts > 0 else 0
    if high_critical_alerts > 0:
        logger.warning(f"Found {high_critical_alerts} high/critical severity issues")
    else:
        logger.info("No high/critical severity issues found")

    # Attempt to notify via configured notifiers once before exiting
    try:
        scanner.load_notification_manager()
        if scanner.notification_manager:
            # Add full scan URL to results if available for notifiers
            if 'full_scan_html_url' in results:
                scanner.config.set('full_scan_html_url', results['full_scan_html_url'])
            scanner.notification_manager.notify_all(results)
    except Exception:
        logger.exception("Failed to run notifiers")

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
