"""Triage filtering for Socket Security Basics.

Fetches triage entries from the Socket API and filters scan components
whose alerts have been triaged (state: ignore or monitor).
"""

import fnmatch
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Triage states that cause a finding to be removed from reports
_SUPPRESSED_STATES = {"ignore", "monitor"}


def fetch_triage_data(sdk: Any, org_slug: str) -> List[Dict[str, Any]]:
    """Fetch all triage alert entries from the Socket API, handling pagination.

    Args:
        sdk: Initialized socketdev SDK instance.
        org_slug: Organization slug for the API call.

    Returns:
        List of triage entry dicts.
    """
    all_entries: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        try:
            response = sdk.triage.list_alert_triage(
                org_slug,
                {"per_page": per_page, "page": page},
            )
        except Exception as exc:
            # Handle insufficient permissions gracefully so the scan
            # continues without triage filtering.
            exc_name = type(exc).__name__
            if "AccessDenied" in exc_name or "Forbidden" in exc_name:
                logger.info(
                    "Triage API access denied (insufficient permissions). "
                    "Skipping triage filtering for this run."
                )
            else:
                logger.warning("Failed to fetch triage data (page %d): %s", page, exc)
            break

        if not isinstance(response, dict):
            logger.warning("Unexpected triage API response type: %s", type(response))
            break

        results = response.get("results") or []
        all_entries.extend(results)

        next_page = response.get("nextPage")
        if next_page is None:
            break
        page = int(next_page)

    logger.debug("Fetched %d triage entries for org %s", len(all_entries), org_slug)
    return all_entries


class TriageFilter:
    """Matches local scan alerts against triage entries and filters them out."""

    def __init__(self, triage_entries: List[Dict[str, Any]]) -> None:
        # Only keep entries whose state suppresses findings
        self.entries = [
            e for e in triage_entries
            if (e.get("state") or "").lower() in _SUPPRESSED_STATES
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_alert_triaged(self, component: Dict[str, Any], alert: Dict[str, Any]) -> bool:
        """Return True if the alert on the given component matches a suppressed triage entry."""
        alert_keys = self._extract_alert_keys(alert)
        if not alert_keys:
            return False

        for entry in self.entries:
            entry_key = entry.get("alert_key")
            if not entry_key:
                continue

            if entry_key not in alert_keys:
                continue

            # alert_key matched; now check package scope
            if self._is_broad_match(entry):
                return True

            if self._package_matches(entry, component):
                return True

        return False

    def filter_components(
        self, components: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Remove triaged alerts from components.

        Returns:
            (filtered_components, triaged_count) where triaged_count is the
            total number of individual alerts removed.
        """
        if not self.entries:
            return components, 0

        filtered: List[Dict[str, Any]] = []
        triaged_count = 0

        for comp in components:
            remaining_alerts: List[Dict[str, Any]] = []
            for alert in comp.get("alerts", []):
                if self.is_alert_triaged(comp, alert):
                    triaged_count += 1
                else:
                    remaining_alerts.append(alert)

            if remaining_alerts:
                new_comp = dict(comp)
                new_comp["alerts"] = remaining_alerts
                filtered.append(new_comp)

        return filtered, triaged_count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_alert_keys(alert: Dict[str, Any]) -> set:
        """Build the set of candidate keys that could match a triage entry's alert_key."""
        keys: set = set()
        props = alert.get("props") or {}

        for field in (
            alert.get("title"),
            alert.get("type"),
            props.get("ruleId"),
            props.get("detectorName"),
            props.get("vulnerabilityId"),
            props.get("cveId"),
        ):
            if field:
                keys.add(str(field))

        return keys

    @staticmethod
    def _is_broad_match(entry: Dict[str, Any]) -> bool:
        """Return True when the triage entry has no package scope (applies globally)."""
        return (
            entry.get("package_name") is None
            and entry.get("package_type") is None
            and entry.get("package_version") is None
            and entry.get("package_namespace") is None
        )

    @staticmethod
    def _version_matches(entry_version: str, component_version: str) -> bool:
        """Check version match, supporting wildcard suffix patterns like '1.2.*'."""
        if not entry_version or entry_version == "*":
            return True
        if not component_version:
            return False
        # fnmatch handles '*' and '?' glob patterns
        return fnmatch.fnmatch(component_version, entry_version)

    @classmethod
    def _package_matches(cls, entry: Dict[str, Any], component: Dict[str, Any]) -> bool:
        """Return True if the triage entry's package scope matches the component."""
        qualifiers = component.get("qualifiers") or {}
        comp_name = component.get("name") or ""
        comp_type = (
            qualifiers.get("ecosystem")
            or qualifiers.get("type")
            or component.get("type")
            or ""
        )
        comp_version = component.get("version") or qualifiers.get("version") or ""
        comp_namespace = qualifiers.get("namespace") or ""

        entry_name = entry.get("package_name")
        entry_type = entry.get("package_type")
        entry_version = entry.get("package_version")
        entry_namespace = entry.get("package_namespace")

        if entry_name is not None and entry_name != comp_name:
            return False
        if entry_type is not None and entry_type.lower() != comp_type.lower():
            return False
        if entry_namespace is not None and entry_namespace != comp_namespace:
            return False
        if entry_version is not None and not cls._version_matches(entry_version, comp_version):
            return False

        return True
