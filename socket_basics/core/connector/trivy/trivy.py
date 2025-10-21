import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any

from .utils import logger
from ..base import BaseConnector
from ...utils import make_json_safe
# Trivy builds canonical components/notifications directly
# Import individual notifier modules
from . import github_pr, slack, ms_teams, ms_sentinel, sumologic, console, jira, webhook, json_notifier

# Import shared formatters
from ...formatters import get_all_formatters

class TrivyScanner(BaseConnector):
    """Trivy container scanner implementation"""

    def __init__(self, config):
        super().__init__(config)

    def is_enabled(self) -> bool:
        """Check if container scanning should be enabled.

        Returns True if either Dockerfile, container image, or vulnerability scanning is enabled.
        This method supports both the new parameter names and legacy ones.
        """
        dockerfile_flag = bool(
            self.config.get('dockerfile_scanning_enabled', False) or self.config.get('dockerfile_enabled', False))
        image_flag = bool(
            self.config.get('container_image_scanning_enabled', False) or self.config.get('image_enabled', False))
        
        # Check if Trivy vulnerability scanning is enabled
        vuln_flag = bool(self.config.get('trivy_vuln_enabled', False))
        
        return dockerfile_flag or image_flag or vuln_flag

    def scan(self) -> Dict[str, Any]:
        """Run both Dockerfile and Image scanning"""
        if not self.is_enabled():
            logger.info("Container scanning disabled, skipping Trivy")
            return {}

        results_map: Dict[str, Any] = {}
        all_notifications: List[List[str]] = []

        # Run Dockerfile scanning
        try:
            dockerfile_results = self.scan_dockerfiles() or {}
            if isinstance(dockerfile_results, dict):
                results_map.update(dockerfile_results)
        except Exception:
            logger.exception('Trivy: dockerfile scan failed')

        # Run Image scanning
        try:
            image_results = self.scan_images() or {}
            if isinstance(image_results, dict):
                results_map.update(image_results)
        except Exception:
            logger.exception('Trivy: image scan failed')
        
        # Run Trivy vulnerability scanning
        try:
            vuln_results = self.scan_vulnerabilities() or {}
            if isinstance(vuln_results, dict):
                results_map.update(vuln_results)
        except Exception:
            logger.exception('Trivy: vulnerability scan failed')
        
        try:
            # The connector produces a mapping of id->component in results_map.
            # Convert to canonical components list and let connector build
            # presentation-ready notification tables via notification_rows().
            components_list: List[Dict[str, Any]] = []
            mapping: Dict[str, Any] = {}
            if isinstance(results_map, dict):
                # results_map may already be mapping id->component
                all_vals = []
                for k, v in results_map.items():
                    if isinstance(v, dict):
                        mapping[k] = v
                        all_vals.append(v)
                components_list = all_vals

            # Build notifications using new shared formatters
            # Determine scan type based on component properties
            scan_type = self._detect_scan_type(components_list)
            
            # Get the first image/dockerfile name from config for the title
            item_name = "Unknown"
            images_str = self.config.get('container_images', '') or self.config.get('container_images_to_scan', '') or self.config.get('docker_images', '')
            if images_str:
                if isinstance(images_str, list):
                    item_name = images_str[0] if images_str else "Unknown"
                else:
                    images = [img.strip() for img in str(images_str).split(',') if img.strip()]
                    item_name = images[0] if images else "Unknown"
            else:
                dockerfiles = self.config.get('dockerfiles', '')
                if dockerfiles:
                    if isinstance(dockerfiles, list):
                        item_name = dockerfiles[0] if dockerfiles else "Unknown"
                    else:
                        docker_list = [df.strip() for df in str(dockerfiles).split(',') if df.strip()]
                        item_name = docker_list[0] if docker_list else "Unknown"
            
            # For vuln scanning, use workspace name if item_name is still Unknown
            if scan_type == 'vuln' and item_name == "Unknown":
                try:
                    workspace = self.config.workspace
                    item_name = os.path.basename(str(workspace))
                except Exception:
                    item_name = "Workspace"

            notifications_by_notifier = self.generate_notifications(components_list, item_name, scan_type)

            return {'components': components_list, 'notifications': notifications_by_notifier}
        except Exception:
            logger.exception('Trivy: normalization failed')
            return {'components': list(results_map.values()), 'notifications': {}}

    def scan_dockerfiles(self) -> Dict[str, Any]:
        """Run Trivy Dockerfile scanning"""
        # Consider both new and legacy dockerfile flags
        dockerfile_enabled = self.config.get('dockerfile_scanning_enabled', False) or self.config.get(
            'dockerfile_enabled', False)
        if not dockerfile_enabled:
            logger.info("Dockerfile scanning disabled, skipping Trivy Dockerfile")
            return {}

        dockerfiles = self.config.get('dockerfiles', '')
        if isinstance(dockerfiles, str):
            dockerfiles = [f.strip() for f in dockerfiles.split(',') if f.strip()]
        elif isinstance(dockerfiles, list):
            dockerfiles = [str(f).strip() for f in dockerfiles if str(f).strip()]
        else:
            dockerfiles = []

        # Try to detect changed Dockerfiles even if none explicitly configured
        changed_files = self.config.get('changed_files', []) if hasattr(self.config, '_config') else []
        if not changed_files:
            try:
                from socket_basics.core.config import _detect_git_changed_files
                changed_files = _detect_git_changed_files(str(self.config.workspace), mode='staged')
            except Exception:
                changed_files = []

        # If explicit dockerfiles are not set, but changed Dockerfiles exist, use them
        if not dockerfiles and changed_files:
            # Filter changed files for Dockerfile candidates
            possible = []
            for cf in changed_files:
                base = Path(cf).name
                if base == 'Dockerfile' or 'dockerfile' in base.lower() or base.lower().endswith('.dockerfile'):
                    if (self.config.workspace / cf).exists():
                        possible.append(cf)
            if possible:
                dockerfiles = possible

        if not dockerfiles:
            logger.info("No Dockerfiles specified, skipping Trivy Dockerfile scanning")
            return {}

        logger.info("Running Trivy Dockerfile scanning")
        results = {}

        # If changed_files is provided, prefer scanning only changed Dockerfiles
        changed_files = self.config.get('changed_files', []) if hasattr(self.config, '_config') else []
        # Fallback: attempt to detect staged changed files if none present
        if not changed_files:
            try:
                # import helper from config module
                from socket_basics.core.config import _detect_git_changed_files
                changed_files = _detect_git_changed_files(str(self.config.workspace), mode='staged')
            except Exception:
                changed_files = []
        if changed_files:
            # Filter changed files down to ones that are Dockerfiles or named 'Dockerfile'
            changed_dockerfiles = []
            for cf in changed_files:
                cf_path = Path(cf)
                base = cf_path.name
                if base == 'Dockerfile' or base.lower().endswith('dockerfile') or base.lower().endswith(
                        '.dockerfile') or 'dockerfile' in base.lower():
                    # Ensure the file exists in workspace
                    full = self.config.workspace / cf
                    if full.exists():
                        changed_dockerfiles.append(cf)

            if changed_dockerfiles:
                logger.info(f"Detected {len(changed_dockerfiles)} changed Dockerfile(s); restricting Trivy to them")
                dockerfiles = changed_dockerfiles

        for dockerfile in dockerfiles:
            # Resolve dockerfile path: prefer given path if it exists, otherwise join with workspace
            candidate_a = Path(dockerfile)
            candidate_b = self.config.workspace / dockerfile
            if candidate_a.exists():
                dockerfile_path = candidate_a
            elif candidate_b.exists():
                dockerfile_path = candidate_b
            else:
                logger.warning(f"Dockerfile not found: {candidate_a} or {candidate_b}")
                continue

            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                    cmd = [
                        'trivy',
                        'config',
                        '--format', 'json',
                        '--output', temp_file.name,
                        str(dockerfile_path)
                    ]

                    logger.info(f"Running: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)

                    if result.returncode != 0:
                        logger.error(f"Trivy dockerfile scan failed for {dockerfile}: {result.stderr}")
                        continue

                    with open(temp_file.name, 'r') as f:
                        trivy_output = json.load(f)

                    dockerfile_results = self._process_dockerfile_results(trivy_output, dockerfile)
                    # dockerfile_results is a dict mapping id->component
                    if isinstance(dockerfile_results, dict):
                        results.update(dockerfile_results)

            except FileNotFoundError:
                logger.error("Trivy not found. Please install Trivy")
            except Exception as e:
                logger.error(f"Error running Trivy on {dockerfile}: {e}")
            finally:
                if 'temp_file' in locals():
                    try:
                        os.unlink(temp_file.name)
                    except:
                        pass

        return results

    def scan_images(self) -> Dict[str, Any]:
        """Run Trivy image scanning"""
        # Check both new and legacy parameter names for images
        images_str = self.config.get('container_images', '') or self.config.get('container_images_to_scan', '') or self.config.get('docker_images', '')
        
        # Also accept list types if provided programmatically
        if isinstance(images_str, list):
            images = [img for img in images_str if img]
        else:
            images = [img.strip() for img in str(images_str).split(',') if img.strip()]

        if not images:
            logger.debug("No Docker images specified, skipping Trivy Image scanning")
            return {}

        # Consider both new and legacy image flags (auto-enabled if images provided)
        image_enabled = self.config.get('container_image_scanning_enabled', False) or self.config.get('image_enabled', False) or bool(images)
        if not image_enabled:
            logger.info("Image scanning disabled, skipping Trivy Image")
            return {}

        logger.info("Running Trivy Image scanning")
        results: Dict[str, Any] = {}

        for image in images:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                    cmd = [
                        'trivy',
                        'image',
                        '--format', 'json',
                        '--output', temp_file.name,
                        image
                    ]

                    logger.info(f"Running: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)

                    if result.returncode != 0:
                        logger.error(f"Trivy image scan failed for {image}: {result.stderr}")
                        continue

                    with open(temp_file.name, 'r') as f:
                        trivy_output = json.load(f)

                    image_results = self._process_image_results(trivy_output, image)
                    if isinstance(image_results, dict):
                        results.update(image_results)

            except FileNotFoundError:
                logger.error("Trivy not found. Please install Trivy")
            except Exception as e:
                logger.error(f"Error running Trivy on {image}: {e}")
            finally:
                if 'temp_file' in locals():
                    try:
                        os.unlink(temp_file.name)
                    except:
                        pass

        return results

    def scan_vulnerabilities(self) -> Dict[str, Any]:
        """Run Trivy filesystem scanning for vulnerabilities"""
        vuln_enabled = self.config.get('trivy_vuln_enabled', False)
        
        if not vuln_enabled:
            logger.info("Trivy vulnerability scanning disabled, skipping")
            return {}
        
        logger.info("Running Trivy filesystem vulnerability scanning")
        results: Dict[str, Any] = {}
        
        # Get the workspace path
        workspace_path = self.config.workspace
        
        # Check for changed files to restrict scanning
        changed_files = self.config.get('changed_files', []) if hasattr(self.config, '_config') else []
        if not changed_files:
            try:
                from socket_basics.core.config import _detect_git_changed_files
                changed_files = _detect_git_changed_files(str(self.config.workspace), mode='staged')
            except Exception:
                changed_files = []
        
        # If we have changed files, scan only those directories
        scan_paths = []
        if changed_files:
            # Extract unique directories from changed files
            dirs = set()
            for cf in changed_files:
                cf_path = Path(cf)
                # Get the parent directory or the file itself if it's a manifest
                if cf_path.suffix in ['.json', '.lock', '.toml', '.txt', '.gradle', '.xml', '.podspec', '.swift']:
                    dirs.add(str(cf_path.parent) if cf_path.parent != Path('.') else '.')
                else:
                    dirs.add(str(cf_path.parent) if cf_path.parent != Path('.') else '.')
            
            # Convert relative paths to absolute
            for d in dirs:
                abs_path = workspace_path / d if not Path(d).is_absolute() else Path(d)
                if abs_path.exists():
                    scan_paths.append(abs_path)
            
            if scan_paths:
                logger.info(f"Restricting Trivy scan to {len(scan_paths)} changed directory(ies)")
        
        # If no changed files or no valid paths, scan entire workspace
        if not scan_paths:
            scan_paths = [workspace_path]
        
        for scan_path in scan_paths:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                    cmd = [
                        'trivy',
                        'fs',
                        '--format', 'json',
                        '--output', temp_file.name,
                        '--scanners', 'vuln',
                        str(scan_path)
                    ]
                    
                    logger.info(f"Running: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        logger.error(f"Trivy vulnerability scan failed for {scan_path}: {result.stderr}")
                        continue
                    
                    with open(temp_file.name, 'r') as f:
                        trivy_output = json.load(f)
                    
                    vuln_results = self._process_vulnerability_results(trivy_output)
                    if isinstance(vuln_results, dict):
                        results.update(vuln_results)
                        
            except FileNotFoundError:
                logger.error("Trivy not found. Please install Trivy")
            except Exception as e:
                logger.error(f"Error running Trivy vulnerability scan for {scan_path}: {e}")
            finally:
                if 'temp_file' in locals():
                    try:
                        os.unlink(temp_file.name)
                    except:
                        pass
        
        return results

    def _convert_to_socket_facts(self, raw_results: Any) -> Dict[str, Any]:
        """Convert raw Trivy results to Socket facts format

        This method implements the BaseConnector interface.
        Since Trivy has multiple scan types, this method delegates to the appropriate
        processing methods based on the result structure.
        """
        # This is a unified method that can handle both dockerfile and image results
        # The scan() method already processes results appropriately
        if isinstance(raw_results, dict):
            return raw_results
        return {}

    def _process_dockerfile_results(self, trivy_output: Dict[str, Any], dockerfile: str) -> Dict[str, Any]:
        """Convert Trivy Dockerfile results to Socket facts format"""
        results = trivy_output.get('Results', [])

        if not results:
            return {}

        import hashlib
        # Create a single component per Dockerfile and append all misconfiguration alerts
        try:
            from pathlib import Path as _P
            p = _P(dockerfile)
            try:
                ws = getattr(self.config, 'workspace', None)
                ws_root = getattr(ws, 'path', None) or getattr(ws, 'root', None) or ws
                if ws and not p.is_absolute():
                    p = _P(ws) / dockerfile
                # If path includes workspace prefix like '../NodeGoat' or 'NodeGoat', strip it
                if ws_root:
                    try:
                        ws_name = os.path.basename(str(ws_root))
                        parts = str(p).split(os.sep)
                        if parts and (parts[0] == ws_name or (
                                len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == ws_name)):
                            if parts[0] == ws_name:
                                parts = parts[1:]
                            else:
                                parts = parts[2:]
                            p = _P(os.path.join(*parts)) if parts else _P('')
                    except Exception:
                        pass
            except Exception:
                pass
            norm = str(p.as_posix())
            cid = hashlib.sha256(norm.encode('utf-8')).hexdigest()
        except Exception:
            import hashlib as _hash
            cid = _hash.sha256(str(dockerfile).encode('utf-8')).hexdigest()

        component = {
            "id": cid,
            "type": "generic",
            "name": f"{dockerfile}",
            "internal": True,
            "version": "",
            "direct": True,
            "dev": False,
            "dead": False,
            "dependencies": [],
            "manifestFiles": [{"file": dockerfile}] if dockerfile else [],
            "alerts": [],
            "qualifers": {
                "ecosystem": "dockerfile"
            }
        }

        for result in results:
            misconfigurations = result.get('Misconfigurations', [])
            for misconfig in misconfigurations:
                alert = self._create_dockerfile_alert(misconfig, dockerfile)
                if alert:
                    component["alerts"].append(alert)

        return {cid: component}

    def _process_image_results(self, trivy_output: Dict[str, Any], image: str) -> Dict[str, Any]:
        """Convert Trivy Image results to Socket facts format"""
        results = trivy_output.get('Results', [])

        if not results:
            return {}

        import hashlib
        components: Dict[str, Any] = {}
        package_components: Dict[str, Any] = {}
        package_ids: List[str] = []

        # Group vulnerabilities by package to create package components
        for result in results:
            result_type = result.get('Type', 'unknown')
            result_class = result.get('Class', 'unknown')

            # Map Trivy type to Socket ecosystem and component type
            ecosystem, component_type = self._get_socket_ecosystem(result_type)

            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                pkg_name = vuln.get('PkgName') or vuln.get('Package') or 'unknown'
                installed_version = vuln.get('InstalledVersion') or vuln.get('FixedVersion') or 'unknown'

                # Create unique package component ID
                package_seed = f"{image}:{pkg_name}@{installed_version}:{ecosystem}"
                package_id = hashlib.sha256(package_seed.encode('utf-8')).hexdigest()

                # Create package component if it doesn't exist
                if package_id not in package_components:
                    package_components[package_id] = {
                        "id": package_id,
                        # "type": component_type,  # Use Socket ecosystem type if available
                        "type": "generic",
                        "name": pkg_name,
                        "internal": True,
                        "version": installed_version,
                        "direct": False,
                        "dev": False,
                        "dead": False,
                        "dependencies": [],
                        "manifestFiles": [{"file": image}],
                        "alerts": [],
                        "qualifiers": {
                            "ecosystem": ecosystem
                        },
                        # "topLevelAncestors": []  # Will be set later
                    }
                    package_ids.append(package_id)

                # Create alert and add to package component
                alert = self._create_image_alert(vuln, image, ecosystem or 'deb')
                if alert:
                    package_components[package_id]["alerts"].append(alert)

        # Create top-level image component
        image_version = "latest"  # Default version
        if ":" in image and not image.split(":")[-1].startswith("sha256"):
            image_parts = image.split(":")
            image_version = image_parts[-1]
            image_name = ":".join(image_parts[:-1])
        else:
            image_name = image

        image_seed = f"image:{image}"
        image_id = hashlib.sha256(image_seed.encode('utf-8')).hexdigest()

        image_component = {
            "id": image_id,
            "type": "generic",
            "name": image_name,
            "internal": True,
            "version": image_version,
            "subPath": f"image:{image}",
            "direct": True,
            "dev": False,
            "dead": False,
            "dependencies": package_ids,
            "manifestFiles": [{"file": image}],
            "alerts": []
        }

        # Set topLevelAncestors for all package components
        # for package_id in package_ids:
        #     package_components[package_id]["topLevelAncestors"] = [image_id]

        # Combine all components (packages first, then image)
        components.update(package_components)
        components[image_id] = image_component

        return components

    def _get_socket_ecosystem(self, trivy_type: str) -> tuple[str, str]:
        """Map Trivy type to Socket ecosystem and component type.
        
        Returns:
            tuple: (ecosystem, component_type) where component_type is the Socket supported type
                   or 'generic' if not a Socket supported ecosystem
        """
        # Supported Socket ecosystems
        socket_ecosystems = {
            'npm', 'pypi', 'maven', 'cargo', 'gem', 'golang', 
            'nuget', 'github', 'chrome', 'huggingface', 'vscode'
        }
        
        # Map Trivy types to Socket ecosystems
        trivy_to_socket = {
            # Node.js
            'node-pkg': ('npm', 'npm'),
            'npm': ('npm', 'npm'),
            'yarn': ('npm', 'npm'),
            'pnpm': ('npm', 'npm'),
            
            # Python
            'python-pkg': ('pypi', 'pypi'),
            'pip': ('pypi', 'pypi'),
            'pipenv': ('pypi', 'pypi'),
            'poetry': ('pypi', 'pypi'),
            
            # Java
            'java-archive': ('maven', 'maven'),
            'jar': ('maven', 'maven'),
            'pom': ('maven', 'maven'),
            'gradle': ('maven', 'maven'),
            
            # Rust
            'rust-crate': ('cargo', 'cargo'),
            'cargo': ('cargo', 'cargo'),
            'cargo-lock': ('cargo', 'cargo'),
            
            # Ruby
            'ruby-gem': ('gem', 'gem'),
            'bundler': ('gem', 'gem'),
            'gemspec': ('gem', 'gem'),
            
            # Go
            'golang': ('golang', 'golang'),
            'gomod': ('golang', 'golang'),
            'go-module': ('golang', 'golang'),
            'go.mod': ('golang', 'golang'),
            
            # .NET
            'nuget': ('nuget', 'nuget'),
            'dotnet-core': ('nuget', 'nuget'),
            'packages-lock': ('nuget', 'nuget'),
            
            # Others that aren't Socket ecosystems
            'composer': ('composer', 'generic'),
            'php-composer': ('composer', 'generic'),
            'conan': ('conan', 'generic'),
            'cocoapods': ('cocoapods', 'generic'),
            'swift': ('cocoapods', 'generic'),
            'hex': ('hex', 'generic'),
            'apk': ('apk', 'generic'),
            'deb': ('deb', 'generic'),
            'debian': ('deb', 'generic'),
            'ubuntu': ('deb', 'generic'),
            'rpm': ('rpm', 'generic'),
            'redhat': ('rpm', 'generic'),
            'centos': ('rpm', 'generic'),
            'fedora': ('rpm', 'generic'),
            'amazon': ('rpm', 'generic'),
            'oracle': ('rpm', 'generic'),
            'photon': ('rpm', 'generic'),
            'suse': ('rpm', 'generic'),
        }
        
        # Normalize the trivy_type to lowercase
        trivy_type_lower = trivy_type.lower()
        
        if trivy_type_lower in trivy_to_socket:
            ecosystem, component_type = trivy_to_socket[trivy_type_lower]
            return ecosystem, component_type
        
        # Default fallback
        return trivy_type, 'generic'

    def _process_vulnerability_results(self, trivy_output: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Trivy vulnerability results to Socket facts format"""
        results = trivy_output.get('Results', [])
        
        if not results:
            return {}
        
        import hashlib
        components: Dict[str, Any] = {}
        
        # Process each result (which may contain multiple vulnerabilities)
        for result in results:
            result_type = result.get('Type', 'unknown')
            result_class = result.get('Class', 'unknown')
            target = result.get('Target', 'unknown')
            
            # Map Trivy type to Socket ecosystem
            ecosystem, component_type = self._get_socket_ecosystem(result_type)
            
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                pkg_name = vuln.get('PkgName') or vuln.get('PkgID') or 'unknown'
                installed_version = vuln.get('InstalledVersion') or 'unknown'
                
                # Create unique package component ID
                package_seed = f"trivy:{pkg_name}@{installed_version}:{ecosystem}"
                package_id = hashlib.sha256(package_seed.encode('utf-8')).hexdigest()
                
                # Create package component if it doesn't exist
                if package_id not in components:
                    components[package_id] = {
                        "id": package_id,
                        # "type": component_type,  # Use Socket ecosystem type if available
                        "type": "generic",
                        "name": pkg_name,
                        "internal": True,
                        "version": installed_version,
                        "direct": True,
                        "dev": False,
                        "dead": False,
                        "dependencies": [],
                        "manifestFiles": [{"file": target}] if target != 'unknown' else [],
                        "alerts": [],
                        "subPath": f"trivy:{ecosystem}"
                    }
                
                # Create alert and add to package component
                alert = self._create_vulnerability_alert(vuln, ecosystem, target, result_type)
                if alert:
                    components[package_id]["alerts"].append(alert)
        
        return components

    def _create_dockerfile_alert(self, misconfig: Dict[str, Any], dockerfile: str) -> Dict[str, Any]:
        """Create a generic alert from a Trivy Dockerfile misconfiguration"""
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }

        severity = severity_map.get(misconfig.get('Severity', 'LOW'), 'low')
        rule_id = misconfig.get('ID', 'unknown')
        try:
            if isinstance(rule_id, str) and rule_id.startswith('socket_basics.rules.'):
                rule_id = rule_id.replace('socket_basics.rules.', '', 1)
        except Exception:
            pass
        title = misconfig.get('Title', 'Configuration issue')
        description = misconfig.get('Message', 'Dockerfile configuration issue detected')

        markdown_content = f"""## Dockerfile Configuration Issue: {rule_id}

### Description
{description}

### File Location
- **Dockerfile**: `{dockerfile}`
- **Rule ID**: {rule_id}

### Issue Details
{misconfig.get('Message', 'No additional details available')}

### Resolution
{misconfig.get('Resolution', 'Review Dockerfile configuration and apply security best practices')}

### Security Impact
Dockerfile misconfigurations can lead to:
- Privilege escalation vulnerabilities
- Information disclosure
- Increased attack surface
- Compliance violations
"""

        return {
            "type": "generic",
            "severity": severity,
            "title": f"Dockerfile: {title}",
            "description": description,
            "category": "vulnerability",
            "subType": "dockerfile",
            "generatedBy": "trivy-dockerfile",
            "action": self.config.get_action_for_severity(severity),
            "props": {
                "ruleId": rule_id,
                "dockerfile": dockerfile,
                "connector": "Trivy Dockerfile Scanning",
                "scanType": "dockerfile",
                "impact": severity,
                "resolution": misconfig.get('Resolution', ''),
                # "references": misconfig.get('References', []),
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }

    def _get_cve_alert_type(self, severity: str, vuln_id: str) -> str:
        """Get the appropriate alert type for CVE findings based on severity"""
        # Only use CVE-specific types for actual CVE identifiers
        if not vuln_id.startswith('CVE-'):
            return "generic"

        severity_to_cve_type = {
            'critical': 'criticalCVE',
            'high': 'cve',
            'medium': 'mediumCVE',
            'low': 'mildCVE'
        }
        return severity_to_cve_type.get(severity, 'generic')

    def _create_image_alert(self, vuln: Dict[str, Any], image: str, ecosystem: str = 'deb') -> Dict[str, Any]:
        """Create a CVE alert from a Trivy image vulnerability"""
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }

        severity = severity_map.get(vuln.get('Severity', 'LOW'), 'low')
        vuln_id = vuln.get('VulnerabilityID', 'unknown')
        try:
            if isinstance(vuln_id, str) and vuln_id.startswith('socket_basics.rules.'):
                vuln_id = vuln_id.replace('socket_basics.rules.', '', 1)
        except Exception:
            pass
        title = vuln.get('Title', 'Vulnerability detected')
        description = vuln.get('Description', 'Container image vulnerability detected')

        # Get the appropriate alert type for CVE findings using the severity mapping
        alert_type = self._get_cve_alert_type(severity, vuln_id)

        # Get package info
        pkg_name = vuln.get('PkgName', 'unknown')
        installed_version = vuln.get('InstalledVersion', 'unknown')
        fixed_version = vuln.get('FixedVersion', 'Not available')

        markdown_content = f"""## Container Image Vulnerability: {vuln_id}

### Vulnerability Details
- **CVE ID**: {vuln_id}
- **Package**: {pkg_name}
- **Installed Version**: {installed_version}
- **Fixed Version**: {fixed_version}
- **Severity**: {severity.upper()}

### Description
{description}

### Image Details
- **Image**: `{image}`
- **Package Path**: {vuln.get('PkgPath', 'N/A')}

### CVSS Score
{vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 'Not available')}

### Remediation
{"Update to version " + fixed_version if fixed_version != "Not available" else "No fix available yet. Consider using alternative packages or implementing additional security controls."}

### Impact Assessment
Container vulnerabilities can lead to:
- Container escape
- Privilege escalation  
- Data exfiltration
- Denial of service
"""

        # Build purl-like locator when possible (best-effort)
        purl = None
        try:
            # prefer explicit installed version, then fixed version, then 'unknown'
            installed_version = vuln.get('InstalledVersion') or vuln.get('FixedVersion') or 'unknown'
            pkg_name = pkg_name or vuln.get('Package') or 'unknown'
            if pkg_name:
                # Use the ecosystem from the Trivy result type
                purl = f"pkg:{ecosystem}/{pkg_name}@{installed_version}"
        except Exception:
            purl = None

        # title_text = f"{vuln_id} in {pkg_name}"
        title_text = severity.capitalize() + " CVE"

        return {
            # "type": alert_type,  # Use the CVE type mapping
            "type": "generic",
            "severity": severity,
            "title": title_text,
            "description": f"{title} in package {pkg_name}",
            "category": "vulnerability",
            "subType": "container-image",
            "generatedBy": "trivy-image",
            "action": self.config.get_action_for_severity(severity),
            "props": {
                "vulnerabilityId": vuln_id,
                "packageName": pkg_name,
                "installedVersion": installed_version,
                "fixedVersion": fixed_version,
                "image": image,
                "connector": "Trivy Image Scanning",
                "scanType": "image",
                "cvssScore": vuln.get('CVSS', {}).get('nvd', {}).get('V3Score'),
                "impact": severity,
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }

    def _create_vulnerability_alert(self, vuln: Dict[str, Any], ecosystem: str, target: str, trivy_type: str) -> Dict[str, Any]:
        """Create a CVE alert from a Trivy vulnerability"""
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        
        severity = severity_map.get(vuln.get('Severity', 'LOW'), 'low')
        vuln_id = vuln.get('VulnerabilityID', 'unknown')
        try:
            if isinstance(vuln_id, str) and vuln_id.startswith('socket_basics.rules.'):
                vuln_id = vuln_id.replace('socket_basics.rules.', '', 1)
        except Exception:
            pass
        title = vuln.get('Title', 'Vulnerability detected')
        description = vuln.get('Description', 'Package vulnerability detected')
        
        # Get the appropriate alert type for CVE findings using the severity mapping
        alert_type = self._get_cve_alert_type(severity, vuln_id)
        
        # Get package info
        pkg_name = vuln.get('PkgName') or vuln.get('PkgID') or 'unknown'
        installed_version = vuln.get('InstalledVersion', 'unknown')
        fixed_version = vuln.get('FixedVersion', 'Not available')
        
        markdown_content = f"""## Package Vulnerability: {vuln_id}

### Vulnerability Details
- **CVE ID**: {vuln_id}
- **Package**: {pkg_name}
- **Installed Version**: {installed_version}
- **Fixed Version**: {fixed_version}
- **Severity**: {severity.upper()}
- **Ecosystem**: {ecosystem}

### Description
{description}

### File Details
- **Target**: `{target}`

### CVSS Score
{vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 'Not available')}

### Remediation
{"Update to version " + fixed_version if fixed_version != "Not available" else "No fix available yet. Consider using alternative packages or implementing additional security controls."}

### Impact Assessment
Package vulnerabilities can lead to:
- Remote code execution
- Privilege escalation  
- Data exfiltration
- Denial of service
"""
        
        # Build purl-like locator
        purl = None
        try:
            if pkg_name and pkg_name != 'unknown':
                purl = f"pkg:{ecosystem}/{pkg_name}@{installed_version}"
        except Exception:
            purl = None
        
        title_text = severity.capitalize() + " CVE"
        
        return {
            "type": alert_type,  # Use the CVE type mapping
            "severity": severity,
            "title": title_text,
            "description": f"{title} in package {pkg_name}",
            "category": "vulnerability",
            "subType": f"trivy-vuln-{ecosystem}",
            "generatedBy": f"trivy-{ecosystem}",
            "action": self.config.get_action_for_severity(severity),
            "props": {
                "vulnerabilityId": vuln_id,
                "packageName": pkg_name,
                "installedVersion": installed_version,
                "fixedVersion": fixed_version,
                "ecosystem": ecosystem,
                "target": target,
                "connector": f"Trivy Vulnerability Scanning",
                "scanType": "trivy-vuln",
                "cvssScore": vuln.get('CVSS', {}).get('nvd', {}).get('V3Score'),
                "impact": severity,
                "purl": purl,
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }

    # Notification processor for Trivy
    def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
        # Legacy method - returns flat list of rows (not grouped tables)
        # This is kept for backward compatibility
        rows: List[List[str]] = []
        if not processed_results:
            return rows

        for comp in processed_results.values():
            comp_name = str(comp.get('name') or comp.get('id') or '-')
            ctype = comp.get('type')

            for a in comp.get('alerts', []):
                props = a.get('props', {}) or {}
                title = str(a.get('title', '') or props.get('ruleId', ''))
                severity = str(a.get('severity', ''))

                if ctype == 'image' or str(comp.get('subpath', '')).startswith('image:'):
                    # Image vulnerability
                    locator = str(props.get('image') or props.get('dockerImage') or comp_name)
                    if props.get('purl'):
                        location = str(props.get('purl'))
                    elif props.get('packageName'):
                        location = f"pkg:deb/{props.get('packageName')}@{props.get('installedVersion', '')}"
                    else:
                        location = locator
                    rows.append([title, severity, locator, location])
                else:
                    # Dockerfile or other
                    file_loc = str(props.get('dockerfile') or comp_name)
                    resolution = str(props.get('resolution', ''))
                    rows.append([title, severity, file_loc, resolution])

        return rows

    def _detect_scan_type(self, components: List[Dict[str, Any]]) -> str:
        """Detect the type of scan based on component properties.
        
        Returns:
            'vuln' for vulnerability scanning, 'image' for image scanning, 'dockerfile' for dockerfile scanning
        """
        if not components:
            return 'unknown'
        
        # Check first component for indicators
        for comp in components:
            subpath = comp.get('subPath', '')
            qualifiers = comp.get('qualifiers', {})
            ecosystem = qualifiers.get('ecosystem', '')
            
            # Vuln scanning has subPath starting with "trivy:"
            if subpath and subpath.startswith('trivy:'):
                return 'vuln'
            
            # Dockerfile scanning has ecosystem "dockerfile"
            if ecosystem == 'dockerfile':
                return 'dockerfile'
            
            # Image scanning has subPath starting with "image:"
            if subpath and subpath.startswith('image:'):
                return 'image'
        
        # Default to image if we have components with qualifiers/ecosystem
        return 'image'

    def generate_notifications(self, components: List[Dict[str, Any]], item_name: str = "Unknown", 
                               scan_type: str = "image") -> Dict[str, List[Dict[str, str]]]:
        """Generate pre-formatted notifications for all notifier types.

        Args:
            components: List of component dictionaries with alerts
            item_name: Name of the item being scanned
            scan_type: Type of scan - 'vuln', 'image', or 'dockerfile'

        Returns:
            Dictionary mapping notifier keys to lists of notification dictionaries
        """
        if not components:
            return {}

        # Create component mapping and apply severity filtering
        comps_map = {}
        for component in components:
            comp_id = component.get('id') or component.get('name') or str(id(component))
            filtered_alerts = []

            for alert in component.get('alerts', []):
                # Filter by severity - only include alerts that match allowed severities
                alert_severity = (alert.get('severity') or '').strip().lower()
                if alert_severity and hasattr(self,
                                              'allowed_severities') and alert_severity not in self.allowed_severities:
                    continue  # Skip this alert - severity not enabled
                filtered_alerts.append(alert)

            # Only include component if it has filtered alerts
            if filtered_alerts:
                filtered_component = component.copy()
                filtered_component['alerts'] = filtered_alerts
                comps_map[comp_id] = filtered_component

        if not comps_map:
            return {}

        # Build notifications for each notifier type using Trivy-specific modules
        notifications_by_notifier = {}
        notifications_by_notifier['github_pr'] = github_pr.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['slack'] = slack.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['msteams'] = ms_teams.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['ms_sentinel'] = ms_sentinel.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['sumologic'] = sumologic.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['json'] = json_notifier.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['console'] = console.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['jira'] = jira.format_notifications(comps_map, item_name, scan_type)
        notifications_by_notifier['webhook'] = webhook.format_notifications(comps_map, item_name, scan_type)

        return notifications_by_notifier

    def get_name(self) -> str:
        """Return the display name for this connector"""
        return "Trivy"