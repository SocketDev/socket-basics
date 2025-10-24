#!/usr/bin/env python3
"""
Custom SAST Rules Builder for OpenGrep

Handles loading, parsing, and organizing custom SAST rules from a directory structure.
Groups rules by language and creates temporary rule files for OpenGrep execution.
"""

import logging
import tempfile
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CustomRulesBuilder:
    """Builds custom rule files from a custom rules directory."""
    
    # Map of languages in rule `languages` field to Socket's rule file naming convention
    LANGUAGE_TO_RULE_FILE = {
        'python': 'python.yml',
        'javascript': 'javascript_typescript.yml',
        'typescript': 'javascript_typescript.yml',
        'go': 'go.yml',
        'java': 'java.yml',
        'ruby': 'ruby.yml',
        'php': 'php.yml',
        'c': 'c_cpp.yml',
        'cpp': 'c_cpp.yml',
        'csharp': 'dotnet.yml',
        'c#': 'dotnet.yml',
        'kotlin': 'kotlin.yml',
        'scala': 'scala.yml',
        'swift': 'swift.yml',
        'rust': 'rust.yml',
        'elixir': 'elixir.yml',
        'erlang': 'erlang.yml',
        'objective-c': 'objective-c.yml',
    }
    
    def __init__(self, custom_rules_path: Path):
        """Initialize the custom rules builder.
        
        Args:
            custom_rules_path: Path to the directory containing custom rule files
        """
        self.custom_rules_path = custom_rules_path
        self.temp_dir: Optional[Path] = None
    
    def build_rule_files(self, enabled_languages: List[str]) -> Dict[str, Path]:
        """Build custom rule files from custom rules directory.
        
        Args:
            enabled_languages: List of enabled language rule files (e.g., ['python.yml', 'javascript_typescript.yml'])
        
        Returns:
            Dictionary mapping rule file names to temporary file paths containing custom rules.
            Empty dict if no custom rules found for enabled languages.
        """
        # Group custom rules by target rule file
        rules_by_file = self._collect_rules_by_file(enabled_languages)
        
        if not rules_by_file:
            logger.info("No custom rules found for enabled languages")
            return {}
        
        # Create temporary directory for custom rule files
        self.temp_dir = Path(tempfile.mkdtemp(prefix='socket_custom_rules_'))
        logger.info(f"Creating custom rule files in {self.temp_dir}")
        
        # Write temporary rule files
        return self._write_rule_files(rules_by_file)
    
    def _collect_rules_by_file(self, enabled_languages: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Scan custom rules directory and group rules by target rule file.
        
        Args:
            enabled_languages: List of enabled language rule files
            
        Returns:
            Dictionary mapping rule file names to lists of rules
        """
        rules_by_file: Dict[str, List[Dict[str, Any]]] = {}
        
        # Find all YAML files recursively
        yaml_files = list(self.custom_rules_path.rglob('*.yml')) + list(self.custom_rules_path.rglob('*.yaml'))
        logger.info(f"Found {len(yaml_files)} custom rule files in {self.custom_rules_path}")
        
        for yaml_file in yaml_files:
            try:
                rules = self._parse_rule_file(yaml_file)
                self._categorize_rules(rules, enabled_languages, rules_by_file)
            except Exception as e:
                logger.warning(f"Failed to process custom rule file {yaml_file}: {e}")
                continue
        
        return rules_by_file
    
    def _parse_rule_file(self, yaml_file: Path) -> List[Dict[str, Any]]:
        """Parse a YAML rule file and extract rules.
        
        Args:
            yaml_file: Path to the YAML file
            
        Returns:
            List of rule dictionaries
        """
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'rules' not in data:
            return []
        
        rules = data.get('rules', [])
        if not isinstance(rules, list):
            return []
        
        return [rule for rule in rules if isinstance(rule, dict)]
    
    def _categorize_rules(
        self, 
        rules: List[Dict[str, Any]], 
        enabled_languages: List[str],
        rules_by_file: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        """Categorize rules by target rule file based on their languages.
        
        Args:
            rules: List of rule dictionaries to categorize
            enabled_languages: List of enabled language rule files
            rules_by_file: Dictionary to populate with categorized rules (modified in place)
        """
        for rule in rules:
            # Get languages this rule applies to
            rule_languages = rule.get('languages', [])
            if not rule_languages:
                continue
            
            # Determine which Socket rule file(s) this rule should go into
            target_files = self._determine_target_files(rule_languages, enabled_languages)
            
            # Add rule to each target file
            for target_file in target_files:
                if target_file not in rules_by_file:
                    rules_by_file[target_file] = []
                rules_by_file[target_file].append(rule)
    
    def _determine_target_files(self, rule_languages: List[str], enabled_languages: List[str]) -> set:
        """Determine which rule files a rule should be added to.
        
        Args:
            rule_languages: Languages specified in the rule
            enabled_languages: List of enabled language rule files
            
        Returns:
            Set of target rule file names
        """
        target_files = set()
        
        for lang in rule_languages:
            lang_lower = str(lang).lower()
            if lang_lower in self.LANGUAGE_TO_RULE_FILE:
                target_file = self.LANGUAGE_TO_RULE_FILE[lang_lower]
                # Only include if this language is enabled
                if target_file in enabled_languages:
                    target_files.add(target_file)
        
        return target_files
    
    def _write_rule_files(self, rules_by_file: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Path]:
        """Write custom rule files to temporary directory.
        
        Args:
            rules_by_file: Dictionary mapping rule file names to lists of rules
            
        Returns:
            Dictionary mapping rule file names to temporary file paths
        """
        if not self.temp_dir:
            raise RuntimeError("Temporary directory not initialized")
        
        custom_rule_paths: Dict[str, Path] = {}
        
        for rule_file_name, rules in rules_by_file.items():
            temp_file_path = self.temp_dir / rule_file_name
            rule_data = {'rules': rules}
            
            try:
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False)
                
                custom_rule_paths[rule_file_name] = temp_file_path
                logger.info(f"Created custom rule file {rule_file_name} with {len(rules)} rules")
            except Exception as e:
                logger.error(f"Failed to write custom rule file {temp_file_path}: {e}")
                continue
        
        return custom_rule_paths
    
    def cleanup(self) -> None:
        """Clean up temporary rule files (optional, as temp files are typically auto-cleaned)."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Cleaned up temporary rule directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary rule directory {self.temp_dir}: {e}")
