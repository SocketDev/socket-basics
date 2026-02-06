"""Triage filtering for Socket Security Basics.

Streams the full scan from the Socket API to obtain alert keys, fetches
triage entries, and filters local scan components whose alerts have been
triaged (state: ignore or monitor).
"""

import logging
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

# Triage states that cause a finding to be removed from reports
_SUPPRESSED_STATES = {"ignore", "monitor"}


# ------------------------------------------------------------------
# API helpers
# ------------------------------------------------------------------

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


def stream_full_scan_alerts(
    sdk: Any, org_slug: str, full_scan_id: str
) -> Dict[str, List[Dict[str, Any]]]:
    """Stream a full scan and extract alert keys grouped by artifact.

    Returns:
        Mapping of artifact ID to list of alert dicts.  Each alert dict
        contains at minimum ``key`` and ``type``.  The artifact metadata
        (name, version, type, etc.) is included under a ``_artifact`` key
        in every alert dict for downstream matching.
    """
    try:
        # use_types=False returns a plain dict keyed by artifact ID
        response = sdk.fullscans.stream(org_slug, full_scan_id, use_types=False)
    except Exception as exc:
        exc_name = type(exc).__name__
        if "AccessDenied" in exc_name or "Forbidden" in exc_name:
            logger.info(
                "Full scan stream access denied (insufficient permissions). "
                "Skipping triage filtering for this run."
            )
        else:
            logger.warning("Failed to stream full scan %s: %s", full_scan_id, exc)
        return {}

    if not isinstance(response, dict):
        logger.warning("Unexpected full scan stream response type: %s", type(response))
        return {}

    artifact_alerts: Dict[str, List[Dict[str, Any]]] = {}
    for artifact_id, artifact in response.items():
        if not isinstance(artifact, dict):
            continue
        alerts = artifact.get("alerts") or []
        if not alerts:
            continue
        meta = {
            "artifact_id": artifact_id,
            "artifact_name": artifact.get("name"),
            "artifact_version": artifact.get("version"),
            "artifact_type": artifact.get("type"),
            "artifact_namespace": artifact.get("namespace"),
            "artifact_subpath": artifact.get("subPath") or artifact.get("subpath"),
        }
        enriched = []
        for a in alerts:
            if isinstance(a, dict) and a.get("key"):
                enriched.append({**a, "_artifact": meta})
        if enriched:
            artifact_alerts[artifact_id] = enriched

    total_alerts = sum(len(v) for v in artifact_alerts.values())
    logger.debug(
        "Streamed full scan %s: %d artifact(s), %d alert(s) with keys",
        full_scan_id,
        len(artifact_alerts),
        total_alerts,
    )
    return artifact_alerts


# ------------------------------------------------------------------
# TriageFilter
# ------------------------------------------------------------------

class TriageFilter:
    """Cross-references Socket alert keys against triage entries and
    maps triaged alerts back to local scan components."""

    def __init__(
        self,
        triage_entries: List[Dict[str, Any]],
        artifact_alerts: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        # Build set of suppressed alert keys
        self.triaged_keys: Set[str] = set()
        for entry in triage_entries:
            state = (entry.get("state") or "").lower()
            key = entry.get("alert_key")
            if state in _SUPPRESSED_STATES and key:
                self.triaged_keys.add(key)

        # Flatten all Socket alerts for lookup
        self._socket_alerts: List[Dict[str, Any]] = []
        for alerts in artifact_alerts.values():
            self._socket_alerts.extend(alerts)

        # Build a mapping from (artifact_id, alert_type) to triaged status
        # for fast lookups when matching against local components
        self._triaged_by_artifact: Dict[str, Set[str]] = {}
        for alert in self._socket_alerts:
            if alert.get("key") in self.triaged_keys:
                art_id = alert.get("_artifact", {}).get("artifact_id", "")
                alert_type = alert.get("type") or ""
                self._triaged_by_artifact.setdefault(art_id, set()).add(alert_type)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter_components(
        self, components: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Remove triaged alerts from local components.

        Matches local components to Socket artifacts by component ID, then
        checks each local alert against the set of triaged alert types for
        that artifact.

        Returns:
            (filtered_components, triaged_count)
        """
        if not self.triaged_keys:
            return components, 0

        # Build lookup: component id -> set of triaged Socket alert types
        triaged_types_by_component = self._map_components_to_triaged_types(components)

        if not triaged_types_by_component:
            logger.debug(
                "No local components matched Socket artifacts with triaged alerts"
            )
            return components, 0

        filtered: List[Dict[str, Any]] = []
        triaged_count = 0

        for comp in components:
            comp_id = comp.get("id") or ""
            triaged_types = triaged_types_by_component.get(comp_id)

            if triaged_types is None:
                # Component had no triaged alerts; keep as-is
                filtered.append(comp)
                continue

            remaining_alerts: List[Dict[str, Any]] = []
            for alert in comp.get("alerts", []):
                if self._local_alert_is_triaged(alert, triaged_types):
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

    def _map_components_to_triaged_types(
        self, components: List[Dict[str, Any]]
    ) -> Dict[str, Set[str]]:
        """Map local component IDs to the set of triaged Socket alert types.

        Matches by component ``id`` (which is typically a hash that Socket
        also uses as the artifact ID).
        """
        local_ids = {comp.get("id") for comp in components if comp.get("id")}
        result: Dict[str, Set[str]] = {}
        for comp_id in local_ids:
            triaged = self._triaged_by_artifact.get(comp_id)
            if triaged:
                result[comp_id] = triaged
        return result

    @staticmethod
    def _local_alert_is_triaged(
        alert: Dict[str, Any], triaged_types: Set[str]
    ) -> bool:
        """Check if a local alert matches any of the triaged Socket alert types.

        Socket alert ``type`` values (e.g. ``badEncoding``, ``cve``) are
        compared against the local alert's ``type`` field.  When the local
        alert type is too generic (``"generic"`` or ``"vulnerability"``),
        we fall back to matching on ``title``, ``props.ruleId``, or
        ``props.vulnerabilityId``.
        """
        # Direct type match
        local_type = alert.get("type") or ""
        if local_type and local_type not in ("generic", "vulnerability"):
            return local_type in triaged_types

        # Fallback: match candidate fields against triaged types
        props = alert.get("props") or {}
        candidates = {
            v for v in (
                alert.get("title"),
                props.get("ruleId"),
                props.get("detectorName"),
                props.get("vulnerabilityId"),
                props.get("cveId"),
            )
            if v
        }
        return bool(candidates & triaged_types)
