#!/usr/bin/env python3
"""
Trivy Container Scanner Connector
Handles Trivy Dockerfile and Image scanning with result processing
"""

import json
import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any

from ..base import BaseConnector
# Trivy builds canonical components/notifications directly

logger = logging.getLogger(__name__)


class TrivyScanner(BaseConnector):
    """Trivy container scanner implementation"""
    
    def __init__(self, config):
        super().__init__(config)
    
    def is_enabled(self) -> bool:
        """Check if container scanning should be enabled.

        Returns True if either Dockerfile or container image scanning is enabled.
        This method supports both the new parameter names and legacy ones.
        """
        dockerfile_flag = bool(self.config.get('dockerfile_scanning_enabled', False) or self.config.get('dockerfile_enabled', False))
        image_flag = bool(self.config.get('container_image_scanning_enabled', False) or self.config.get('image_enabled', False))
        return dockerfile_flag or image_flag
    
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

            # Build notification tables from mapping
            try:
                tables = self.notification_rows(mapping)
            except Exception:
                tables = []

            # Fallback: synthesize a simple results table from alerts if needed
            if not tables:
                notifications = []
                for c in components_list:
                    cid = c.get('id') or c.get('name') or ''
                    for a in c.get('alerts', []) or []:
                        path = (a.get('props') or {}).get('filePath') or (a.get('location') or {}).get('path') or c.get('name') or cid
                        line = (a.get('props') or {}).get('startLine') or (a.get('location') or {}).get('line') or ''
                        notifications.append([cid, str(a.get('severity') or ''), a.get('title') or a.get('description') or '', f"{path}:{line}" if line else (path or '')])
                if notifications:
                    tables = [{'title': 'results', 'headers': ['component','severity','title','location'], 'rows': notifications}]

            return {'components': components_list, 'notifications': tables}
        except Exception:
            logger.exception('Trivy: normalization failed')
            return {'components': list(results_map.values()), 'notifications': []}
    
    def scan_dockerfiles(self) -> Dict[str, Any]:
        """Run Trivy Dockerfile scanning"""
        # Consider both new and legacy dockerfile flags
        dockerfile_enabled = self.config.get('dockerfile_scanning_enabled', False) or self.config.get('dockerfile_enabled', False)
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
                if base == 'Dockerfile' or base.lower().endswith('dockerfile') or base.lower().endswith('.dockerfile') or 'dockerfile' in base.lower():
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
                    # dockerfile_results should already be a canonical wrapper
                    if isinstance(dockerfile_results, dict) and isinstance(dockerfile_results.get('components'), list):
                        for c in dockerfile_results.get('components', []):
                            cid = c.get('id') or c.get('name') or ''
                            if cid:
                                results[cid] = c

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
        # Consider both new and legacy image flags
        image_enabled = self.config.get('container_image_scanning_enabled', False) or self.config.get('image_enabled', False)
        if not image_enabled:
            logger.info("Image scanning disabled, skipping Trivy Image")
            return {}

        # Check both new and legacy parameter names for images
        images_str = self.config.get('container_images_to_scan', '') or self.config.get('docker_images', '')
        # Also accept list types if provided programmatically
        if isinstance(images_str, list):
            images = [img for img in images_str if img]
        else:
            images = [img.strip() for img in str(images_str).split(',') if img.strip()]

        if not images:
            logger.info("No Docker images specified, skipping Trivy Image scanning")
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
                        if parts and (parts[0] == ws_name or (len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == ws_name)):
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
            "alerts": []
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

        # For image vulnerabilities, create a component per vulnerability
        # using sha256(image + vuln_id + purl_if_present) so identical
        # vuln hits map across runs and images with purls are distinguished.
        for result in results:
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                vuln_id = vuln.get('VulnerabilityID', 'unknown')
                # build purl from created alert if possible
                purl = None
                try:
                    installed_version = vuln.get('InstalledVersion') or vuln.get('FixedVersion') or 'unknown'
                    pkg_name = vuln.get('PkgName') or vuln.get('Package') or 'unknown'
                    if pkg_name:
                        purl = f"pkg:deb/{pkg_name}@{installed_version}"
                except Exception:
                    purl = None

                seed = f"{image}:{vuln_id}:{purl or ''}"
                cid = hashlib.sha256(seed.encode('utf-8')).hexdigest()

                if cid not in components:
                    components[cid] = {
                        "id": cid,
                        "type": "generic",
                        "name": f"{image}",
                        "internal": True,
                        "version": "",
                        "subpath": f"image:{image}",
                        "direct": True,
                        "dev": False,
                        "dead": False,
                        "dependencies": [],
                        "manifestFiles": [{"file": image}],
                        "alerts": []
                    }

                alert = self._create_image_alert(vuln, image)
                if alert:
                    components[cid]["alerts"].append(alert)

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
        description = misconfig.get('Description', 'Dockerfile configuration issue detected')
        
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

### References
{chr(10).join([f"- [{ref}]({ref})" for ref in misconfig.get('References', [])])}

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
                "tool": "trivy",
                "scanType": "dockerfile",
                "impact": severity,
                "resolution": misconfig.get('Resolution', ''),
                "references": misconfig.get('References', []),
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

    def _create_image_alert(self, vuln: Dict[str, Any], image: str) -> Dict[str, Any]:
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
        
        # Get the appropriate alert type for CVE findings
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

### References
{chr(10).join([f"- [{ref}]({ref})" for ref in vuln.get('References', [])])}

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
                # assume deb-style purl by default; this is best-effort and may be adjusted later
                purl = f"pkg:deb/{pkg_name}@{installed_version}"
        except Exception:
            purl = None

        title_text = f"{vuln_id} in {pkg_name}"

        return {
            "type": alert_type,
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
                "purl": purl,
                "tool": "trivy",
                "scanType": "image",
                "cvssScore": vuln.get('CVSS', {}).get('nvd', {}).get('V3Score'),
                "references": vuln.get('References', []),
                "impact": severity,
                "detailedReport": {
                    "content-type": "text/markdown",
                    "content": markdown_content
                }
            }
        }

    # Notification processor for Trivy
    def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
        # Build canonical list of tables: images and dockerfiles
        tables: List[Dict[str, Any]] = []

        image_groups: Dict[str, List[List[str]]] = {}
        dockerfile_groups: Dict[str, List[List[str]]] = {}

        for comp in processed_results.values():
            comp_name = comp.get('name') or comp.get('id') or '-'
            ctype = q.get('type') or comp.get('type')
            if ctype == 'image' or str(comp.get('subpath', '')).startswith('image:'):
                # treat as image; gather rows
                for a in comp.get('alerts', []):
                    title = a.get('title', '')
                    sev = a.get('severity', '')
                    props = a.get('props', {}) or {}
                    locator = props.get('image') or props.get('dockerImage') or comp_name
                    if props.get('purl'):
                        loc = props.get('purl')
                    elif props.get('packageName'):
                        loc = f"pkg:deb/{props.get('packageName')}@{props.get('installedVersion', '')}"
                    else:
                        loc = ''
                    title_key = props.get('image') or props.get('dockerImage') or comp_name
                    image_groups.setdefault(title_key, []).append([title, sev, locator, loc])
            elif ctype == 'dockerfile' or any('dockerfile' in (mf.get('file') or '').lower() for mf in (comp.get('manifestFiles') or [])):
                for a in comp.get('alerts', []):
                    props = a.get('props', {}) or {}
                    title = props.get('ruleId') or a.get('title') or ''
                    impact = a.get('severity') or ''
                    file_loc = props.get('dockerfile') or comp.get('name') or comp_name
                    dockerfile_groups.setdefault(comp_name, []).append([title, impact, file_loc, props.get('resolution','') or ''])

        # Consolidate image rows per image by (locator, purl, severity) and merge titles
        def _merge_titles(titles: List[str]) -> str:
            if not titles:
                return ''
            suffix = None
            if all(' in ' in t for t in titles):
                cand = titles[0]
                idx = cand.rfind(' in ')
                if idx != -1:
                    s = cand[idx:]
                    if all(t.endswith(s) for t in titles):
                        suffix = s
            if suffix:
                stripped = [t[: t.rfind(' in ')] if ' in ' in t else t for t in titles]
                return ', '.join(stripped) + suffix
            uniq = []
            for t in titles:
                if t not in uniq:
                    uniq.append(t)
            if len(uniq) > 10:
                return ', '.join(uniq[:10]) + f' (+{len(uniq)-10} more)'
            return ', '.join(uniq)

        image_headers = ['Title', 'Severity', 'Image', 'Location']
        for title, rows in image_groups.items():
            keyed: Dict[tuple, List[str]] = {}
            others: List[List[str]] = []
            for r in rows:
                if not isinstance(r, (list, tuple)) or len(r) < 4:
                    others.append(r)
                    continue
                t = str(r[0] or '')
                severity = str(r[1] or '')
                locator = str(r[2] or '')
                purl = str(r[3] or '')
                key = (locator, purl, severity)
                keyed.setdefault(key, []).append(t)

            new_rows: List[List[str]] = []
            for (locator, purl, severity), titles in keyed.items():
                merged = _merge_titles(titles)
                new_rows.append([merged, severity, locator, purl])
            new_rows.extend(others)
            tables.append({'title': title, 'headers': image_headers, 'rows': new_rows})

        # Append dockerfile tables (no special consolidation required beyond grouping)
        dockerfile_headers = ['Title', 'Severity', 'Dockerfile', 'Resolution']
        for df_name, rows in dockerfile_groups.items():
            tables.append({'title': df_name, 'headers': dockerfile_headers, 'rows': rows})

        return tables
