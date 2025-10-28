#!/usr/bin/env python3
"""
OpenGrep SAST Scanner Connector

This connector composes a single OpenGrep command that includes full
language rule files and appends --exclude-rule flags for any rules that
should be skipped. It intentionally does not attempt per-rule fallbacks.
"""

import json
import logging
import os
import subprocess
import tempfile
import yaml
from pathlib import Path
from typing import Dict, Any, List

from ..base import BaseConnector
# Opengrep produces canonical components/notifications directly

# Import individual notifier modules
from . import github_pr, slack, ms_teams, ms_sentinel, sumologic, console, jira, webhook, json_notifier
from .custom_rules import CustomRulesBuilder

# Import shared formatters
from ...formatters import get_all_formatters

logger = logging.getLogger(__name__)


class OpenGrepScanner(BaseConnector):
	def __init__(self, config):
		super().__init__(config)

	def scan(self) -> Dict[str, Any]:
		# Determine enabled rule files
		try:
			rule_files = self.config.build_opengrep_rules() or []
		except Exception:
			rule_files = []

		# If no languages selected and not explicitly allowing all, skip
		if not rule_files and not self.config.get('all_languages_enabled', False):
			logger.debug('No SAST languages enabled; skipping OpenGrep')
			return {}

		targets = self.config.get_scan_targets()

		# Check if custom rules mode is enabled
		custom_rules_path = self.config.get_custom_rules_path()
		custom_rule_files: Dict[str, Path] = {}
		
		if custom_rules_path:
			logger.info(f"Custom SAST rules enabled, loading from: {custom_rules_path}")
			try:
				builder = CustomRulesBuilder(custom_rules_path)
				custom_rule_files = builder.build_rule_files(rule_files)
			except Exception as e:
				logger.error(f"Failed to build custom rule files: {e}", exc_info=True)
				custom_rule_files = {}

		# Locate bundled rules directory for fallback
		module_dir = Path(__file__).resolve().parents[3]
		bundled_rules_dir = module_dir / 'rules'
		rules_dir = self.config.get('opengrep_rules_dir') or (str(bundled_rules_dir) if bundled_rules_dir.exists() else None)
		if not rules_dir:
			logger.error('No rules directory found')
			return {}

		# Read filtered rule definitions if available
		try:
			filtered = self.config.build_filtered_opengrep_rules() or {}
		except Exception:
			filtered = {}

		# Debugging: log computed rule files and filtered rules for diagnosis
		try:
			logger.debug('Computed rule_files for OpenGrep: %s', rule_files)
			logger.debug('Computed filtered rule mapping: %s', filtered)
		except Exception:
			pass

		if self.config.get('all_rules_enabled', False):
			filtered = {}

		config_args: List[str] = []
		
		# Build config_args using custom rules where available, falling back to bundled rules
		# Process all enabled languages - use filtered rules if specified, otherwise use all rules
		for rf in rule_files:
			# Check if we have a custom rule file for this language
			if custom_rule_files and rf in custom_rule_files:
				p = custom_rule_files[rf]
				logger.info(f"Using custom rules for {rf}")
			else:
				# Fall back to bundled rules
				p = Path(rules_dir) / rf
				if not p.exists():
					logger.debug('Rule file missing: %s', p)
					continue
			
			# Check if this language has specific rules enabled (filtered mode)
			if filtered and rf in filtered:
				enabled_ids = filtered[rf]
				logger.debug(f"Using filtered rules for {rf}: {len(enabled_ids)} rules enabled")
				try:
					with open(p, 'r') as fh:
						data = yaml.safe_load(fh) or {}
					all_ids = [r.get('id') for r in (data.get('rules') or []) if r.get('id')]
					to_exclude = [rid for rid in all_ids if rid not in (enabled_ids or [])]
					config_args.extend(['--config', str(p)])
					for ex in to_exclude:
						config_args.extend(['--exclude-rule', ex])
				except Exception:
					logger.debug('Failed reading/parsing rule file %s', p, exc_info=True)
			else:
				# No specific rules configured - use all rules from this file
				logger.debug(f"Using all rules for {rf}")
				config_args.extend(['--config', str(p)])

		# If nothing selected, only include all bundled rule files when the
		# caller explicitly requested all languages or all rules. Otherwise
		# skip scanning to avoid running unrelated language rules.
		if not config_args:
			# If all_rules_enabled is set, include all rule files for the
			# languages that the config reports as enabled (build_opengrep_rules).
			# Only when all_languages_enabled is True should we include every
			# bundled rule file regardless of language flags.
			if self.config.get('all_rules_enabled', False):
				try:
					rule_files = self.config.build_opengrep_rules() or []
					for rf in rule_files:
						p = Path(rules_dir) / rf
						if p.exists():
							config_args.extend(['--config', str(p)])
				except Exception:
					logger.debug('Failed expanding all_rules into specific rule files', exc_info=True)

			if not config_args and self.config.get('all_languages_enabled', False):
				try:
					for p in Path(rules_dir).glob('*.yml'):
						# Skip tests.yml from community rules
						if p.name == 'tests.yml':
							continue
						config_args.extend(['--config', str(p)])
				except Exception:
					pass

			if not config_args:
				logger.debug('No rule files selected and not configured to include all; skipping OpenGrep')
				return {}

		if not config_args:
			logger.error('No valid rule files found')
			return {}

		# Run combined OpenGrep once
		with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
			out_file = tf.name

		cmd = ['opengrep', '--json', '--output', out_file]
		verbose = self.config.get('verbose', False)
		cmd.append('--verbose' if verbose else '--quiet')

		try:
			ws = Path(self.config.workspace)
			if not (ws / '.git').exists():
				cmd.append('-a')
				cmd.append('--no-git-ignore')
		except Exception:
			pass

		cmd.extend(config_args + targets)
		logger.info('Running OpenGrep: %s', ' '.join(cmd))

		try:
			result = subprocess.run(cmd, capture_output=True, text=True)
		except FileNotFoundError:
			logger.error('OpenGrep binary not found')
			try:
				os.unlink(out_file)
			except Exception:
				pass
			return {}

		if verbose and result.stdout:
			logger.debug('OpenGrep stdout: %s', result.stdout)
		if verbose and result.stderr:
			logger.debug('OpenGrep stderr: %s', result.stderr)

		if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
			try:
				with open(out_file, 'r') as fh:
					raw = fh.read()
					data = json.loads(raw)
			except Exception:
				logger.debug('Failed to parse OpenGrep JSON output', exc_info=True)
				data = {}
		else:
			logger.warning('OpenGrep produced no output (combined run)')
			data = {}

		try:
			os.unlink(out_file)
		except Exception:
			pass

		try:
			raw_processed = self._convert_to_socket_facts(data or {})
			# Convert mapping -> canonical wrapper if needed
			if isinstance(raw_processed, dict) and raw_processed and 'components' not in raw_processed and all(isinstance(v, dict) for v in raw_processed.values()):
				raw_processed = {'components': list(raw_processed.values())}
			# raw_processed is now canonical; build socket_facts from it
			socket_facts = raw_processed if isinstance(raw_processed, dict) and isinstance(raw_processed.get('components'), list) else {'components': []}
			notifications = []
			# Build per-subtype notification tables (e.g. 'sast-python',
			# 'sast-golang', 'sast-typescript'). For each subtype present in
			# the alerts, create a table with title=subtype and rows similar
			# to the old notification_rows format.
			wrapper = {'components': socket_facts.get('components', [])}
			try:
				comps_map: Dict[str, Dict[str, Any]] = {c.get('id') or c.get('name'): c for c in socket_facts.get('components', [])}
				
				# Build notifications using new shared formatters
				notifications_by_notifier = self.generate_notifications(wrapper.get('components', []))
				
				if notifications_by_notifier:
					wrapper['notifications'] = notifications_by_notifier
				elif notifications:
					# fallback to old format if needed
					wrapper['notifications'] = [{'title': 'results', 'rows': notifications}]
			except Exception:
				# if grouping fails, fall back to raw notifications
				if notifications:
					# fallback: attach as canonical notifications list
					wrapper['notifications'] = [{'title': 'results', 'rows': notifications}]

			return {'components': wrapper.get('components', []), 'notifications': wrapper.get('notifications', [])}
		except Exception:
			logger.exception('Processing OpenGrep results failed')
			return {'components': [], 'notifications': []}

	def _convert_to_socket_facts(self, raw_results: Any) -> Dict[str, Any]:
		"""Convert OpenGrep JSON output into a mapping of component_id -> component.

		Expected output for the manager is a dict where each value is a component
		dict containing an 'alerts' list. If no alerts are present we return an
		empty dict so the manager treats this as no results.
		"""
		if not raw_results:
			return {}

		# Common shapes: {'components': [ {...}, ... ]} or {'results': [...]}
		out: Dict[str, Any] = {}

		# If opengrep produces a 'results' list (common), convert each finding into
		# a component with a single alert. Group alerts by path so each file is a
		# component that contains its alerts.
		if isinstance(raw_results, dict):
			results = raw_results.get('results') if isinstance(raw_results.get('results'), list) else None
			if isinstance(results, list):
				# group alerts by file path
				comps: Dict[str, Dict[str, Any]] = {}
				for r in results:
					try:
						path = r.get('path') or (r.get('extra', {}) or {}).get('file') or 'unknown'
						
						# Skip files from custom_rules directory - these are rule files, not source code
						# Check if path starts with custom_rules (relative to workspace/cwd)
						try:
							from pathlib import Path as _P
							p = _P(path)
							# Get custom rules path from config
							custom_rules_path = self.config.get_custom_rules_path()
							if custom_rules_path:
								custom_rules_path = Path(custom_rules_path)
								# Check if the file path is inside the custom rules directory
								try:
									# For absolute paths
									if p.is_absolute() and custom_rules_path.is_absolute():
										try:
											p.relative_to(custom_rules_path)
											logger.debug(f"Skipping result from custom_rules directory: {path}")
											continue
										except ValueError:
											pass
									# For relative paths, check if path starts with custom_rules
									else:
										path_str = str(p.as_posix())
										custom_rules_str = str(custom_rules_path.as_posix())
										# Normalize both to relative paths
										if path_str.startswith(custom_rules_str + '/') or path_str == custom_rules_str:
											logger.debug(f"Skipping result from custom_rules directory: {path}")
											continue
										# Also check if just the first component matches (e.g., "custom_rules/...")
										parts = p.parts
										if parts and parts[0] == custom_rules_path.name:
											logger.debug(f"Skipping result from custom_rules directory: {path}")
											continue
								except Exception:
									pass
						except Exception:
							pass
						
						# Normalize path early to strip workspace/temp/custom_rules paths
						normalized_path = path
						try:
							from pathlib import Path as _P
							p = _P(path)
							ws = getattr(self.config, 'workspace', None)
							ws_root = getattr(ws, 'path', None) or getattr(ws, 'root', None) or ws
							if ws_root:
								# If path is absolute and inside workspace, make it relative
								if p.is_absolute():
									try:
										if str(p).startswith(str(ws_root)):
											p = _P(os.path.relpath(str(p), str(ws_root)))
									except Exception:
										pass
								else:
									# Remove leading workspace folder components
									parts = str(p).split(os.sep)
									ws_name = os.path.basename(str(ws_root))
									if parts and (parts[0] == ws_name or (len(parts) >= 2 and parts[0] in ('.', '..') and parts[1] == ws_name)):
										if parts[0] == ws_name:
											parts = parts[1:]
										else:
											parts = parts[2:]
										p = _P(os.path.join(*parts)) if parts else _P('')
							normalized_path = str(p.as_posix())
						except Exception:
							pass
						
						# Preserve original identifier so we can annotate generatedBy when
						# the rule comes from the bundled socket_basics ruleset
						original_check_id = r.get('check_id') or (r.get('extra') or {}).get('rule_id') or ''
						check_id = original_check_id
						# Remove internal namespace prefix if present; connectors own
						# their emitted identifiers and must not expose internal pkg IDs
						# We only want to show the actual rule name from the rules file, not any path/package prefix
						try:
							if isinstance(check_id, str) and '.' in check_id:
								# Extract just the rule name by taking the last segment after the final dot
								# This handles all patterns:
								#   - socket_basics.rules.rule-name -> rule-name
								#   - socket-basics.socket_basics.rules.rule-name -> rule-name
								#   - /tmp/path.socket_custom_rules_XXXX.rule-name -> rule-name
								#   - any.other.prefix.rule-name -> rule-name
								check_id = check_id.split('.')[-1]
						except Exception:
							pass
						severity = ((r.get('extra') or {}).get('severity') or r.get('severity') or '')
						severity_norm = str(severity).lower() if severity is not None else ''
						message = (r.get('extra') or {}).get('message') or r.get('message') or ''
						start = (r.get('start') or {}).get('line')
						end = (r.get('end') or {}).get('line')

						# Normalize severity to one of low/medium/high/critical
						if severity_norm in ('critical', 'error', 'err'):
							sev_label = 'critical'
						elif severity_norm in ('high',):
							sev_label = 'high'
						elif severity_norm in ('medium', 'moderate'):
							sev_label = 'medium'
						elif severity_norm in ('low', 'warning'):
							sev_label = 'low'
						else:
							# default if unknown
							sev_label = 'medium'

						alert = {
							'title': check_id,
							'description': message,
							'severity': sev_label,
							'type': 'generic',
							'location': {
								'start': start,
								'end': end
							},
							'props': {
								'ruleId': check_id,
								'confidence': (r.get('extra') or {}).get('metadata', {}).get('confidence', ''),
								'fingerprint': (r.get('extra') or {}).get('fingerprint') or '',
								# Fill commonly-consumed fields so notifiers can format Location/Lines
								'filePath': normalized_path,
								'startLine': start,
								'endLine': end,
								'codeSnippet': (r.get('extra') or {}).get('lines') or (r.get('extra') or {}).get('snippet') or ''
							}
						}

						# Determine a more specific subtype when possible.
						# Prefer file extension, then check_id naming conventions.
						detected_subtype = None
						try:
							from pathlib import Path as _P
							ext = (_P(normalized_path).suffix or '').lower()
							if ext == '.py' or (isinstance(check_id, str) and check_id.startswith('python-')):
								detected_subtype = 'sast-python'
							elif ext in ('.js', '.ts') or (isinstance(check_id, str) and check_id.startswith('js-')):
								detected_subtype = 'sast-javascript'
							elif ext in ('.go',) or (isinstance(check_id, str) and check_id.startswith('go-')):
								detected_subtype = 'sast-golang'
						except Exception:
							detected_subtype = None

						# Provide required top-level classification fields
						# SAST findings should be classified as vulnerabilities by default
						alert.setdefault('category', 'vulnerability')
						# Ensure generatedBy indicates the originating opengrep flavor
						try:
							# detected_subtype may be like 'sast-python' or 'sast-javascript'
							if detected_subtype:
								# Map 'sast-python' -> 'opengrep-python'
								gen = detected_subtype.replace('sast-', 'opengrep-')
							else:
								gen = 'sast-generic'
							# Force the generatedBy to the opengrep flavor so
							# notifiers can attribute findings correctly.
							alert['generatedBy'] = gen
						except Exception:
							alert['generatedBy'] = 'opengrep'
						if detected_subtype:
							alert['subType'] = detected_subtype
						else:
							alert.setdefault('subType', 'sast-generic')

						# Build component ID from normalized path
						try:
							import hashlib as _hash
							comp_id = _hash.sha256(normalized_path.encode('utf-8')).hexdigest()
						except Exception:
							comp_id = normalized_path

						if comp_id not in comps:
							comps[comp_id] = {
								'id': comp_id,
								'type': 'generic',
								'subPath': detected_subtype,
								'name': normalized_path,
								"internal": True,
								'alerts': []
							}
						
						# Normalize alert action based on disabled rules before adding to component
						from ..normalizer import _normalize_alert
						try:
							alert = _normalize_alert(alert, connector=self)
						except Exception:
							logger.debug('Failed to normalize alert action', exc_info=True)
						
						comps[comp_id]['alerts'].append(alert)
					except Exception:
						logger.debug('Failed to convert single opengrep result to alert', exc_info=True)
				
				# Now add components for ALL files in the workspace (even those without alerts)
				try:
					from ...config import discover_all_files
					import hashlib as _hash
					from pathlib import Path as _P
					
					workspace = getattr(self.config, 'workspace', None)
					if workspace:
						all_files = discover_all_files(str(workspace), respect_gitignore=True)
						logger.debug(f"Discovered {len(all_files)} files in workspace for component generation")
						
						for file_path in all_files:
							# Normalize path and generate component ID (same logic as above)
							try:
								norm = file_path.replace('\\', '/')  # Normalize to forward slashes
								comp_id = _hash.sha256(norm.encode('utf-8')).hexdigest()
								
								# Only add if not already present (files with alerts already have components)
								if comp_id not in comps:
									comps[comp_id] = {
										'id': comp_id,
										'type': 'generic',
										'subPath': 'sast-generic',
										'name': file_path,
										"internal": True,
										'alerts': []
									}
							except Exception:
								logger.debug(f'Failed to create component for file: {file_path}', exc_info=True)
				except Exception as e:
					logger.debug(f'Failed to discover all workspace files: {e}', exc_info=True)
				
				return comps

			# If it's already a mapping of component_id -> component, return all (not just with alerts)
			if all(isinstance(v, dict) for v in raw_results.values()):
				return raw_results

		return {}



	def notification_rows(self, processed_results: Dict[str, Any]) -> List[List[str]]:
		# Legacy method - returns flat list of rows (not grouped tables)
		# This is kept for backward compatibility
		rows: List[List[str]] = []
		if not processed_results:
			return rows
		
		for comp in processed_results.values():
			for a in comp.get('alerts', []):
				props = a.get('props', {}) or {}
				severity = a.get('severity', 'low')
				full_path = props.get('filePath', a.get('location', {}).get('path')) or '-'
				try:
					from pathlib import Path
					file_name = Path(full_path).name
				except Exception:
					file_name = full_path

				row = [
					props.get('ruleId', a.get('title', '')),
					severity,
					file_name,
					full_path,
					f"{props.get('startLine','')}-{props.get('endLine','')}",
					props.get('codeSnippet','') or ''
				]
				rows.append(row)

		return rows
	
	def generate_notifications(self, components: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
		"""Generate pre-formatted notifications for all notifier types.
		
		Args:
			components: List of component dictionaries with alerts
			
		Returns:
			Dictionary mapping notifier keys to lists of notification dictionaries
		"""
		if not components:
			return {}
		
		# Create component mapping for compatibility with connector-specific formatters
		comps_map = {c.get('id') or c.get('name') or str(id(c)): c for c in components}
		
		# Get all alerts grouped by subtype, with severity filtering
		groups: Dict[str, List[Dict[str, Any]]] = {}
		for c in comps_map.values():
			for a in c.get('alerts', []):
				# Filter by severity - only include alerts that match allowed severities
				alert_severity = (a.get('severity') or '').strip().lower()
				if alert_severity and hasattr(self, 'allowed_severities') and alert_severity not in self.allowed_severities:
					continue  # Skip this alert - severity not enabled
				
				st = a.get('subType') or a.get('subtype') or 'sast-generic'
				groups.setdefault(st, []).append({'component': c, 'alert': a})
		
		if not groups:
			return {}
		
		# Build notifications for each notifier type using OpenGrep-specific modules
		notifications_by_notifier = {}
		notifications_by_notifier['github_pr'] = github_pr.format_notifications(groups)
		notifications_by_notifier['slack'] = slack.format_notifications(groups)
		notifications_by_notifier['msteams'] = ms_teams.format_notifications(groups)
		notifications_by_notifier['ms_sentinel'] = ms_sentinel.format_notifications(groups)
		notifications_by_notifier['sumologic'] = sumologic.format_notifications(groups)
		notifications_by_notifier['json'] = json_notifier.format_notifications(groups)
		notifications_by_notifier['console'] = console.format_notifications(groups)
		notifications_by_notifier['jira'] = jira.format_notifications(groups)
		notifications_by_notifier['webhook'] = webhook.format_notifications(groups)
		
		return notifications_by_notifier

