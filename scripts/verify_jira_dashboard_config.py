#!/usr/bin/env python3
"""
Verify that dashboard-provided Jira config (via Socket API) flows into JiraNotifier.

This script does NOT call Jira. It only loads Socket Basics config, builds the
NotificationManager, and inspects JiraNotifier params.

Expected env vars:
- SOCKET_SECURITY_API_KEY or SOCKET_SECURITY_API_TOKEN (required)
- SOCKET_ORG or SOCKET_ORG_SLUG (recommended; auto-discovery is attempted)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from socket_basics.core.config import merge_json_and_env_config
from socket_basics.core.notification.manager import NotificationManager


def _summarize_jira(notifier) -> dict:
    return {
        "server": getattr(notifier, "server", None),
        "project": getattr(notifier, "project", None),
        "email": getattr(notifier, "email", None),
        "api_token_present": bool(getattr(notifier, "api_token", None)),
    }


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    try:
        for raw_line in dotenv_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'").strip('"')
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        # Best-effort; do not fail if .env parsing is imperfect
        pass


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    repo_root = Path(__file__).resolve().parents[1]
    _load_dotenv(repo_root / ".env")

    try:
        config_dict = merge_json_and_env_config()
    except Exception as exc:
        print(f"ERROR: failed to load config: {exc}")
        return 2

    # Load notifications.yaml and build manager
    try:
        import yaml

        cfg_path = repo_root / "socket_basics" / "notifications.yaml"
        notif_cfg = None
        if cfg_path.exists():
            with open(cfg_path, "r") as f:
                notif_cfg = yaml.safe_load(f)
    except Exception as exc:
        print(f"ERROR: failed to load notifications.yaml: {exc}")
        return 2

    nm = NotificationManager(notif_cfg, app_config=config_dict)
    nm.load_from_config()

    jira_notifiers = [n for n in nm.notifiers if getattr(n, "name", "").lower() == "jira"]
    if not jira_notifiers:
        print("Jira notifier not enabled. Check that dashboard config includes jira_url or env provides JIRA_URL.")
        return 1

    # Print details for first Jira notifier
    summary = _summarize_jira(jira_notifiers[0])
    print("Jira notifier config summary:")
    print(json.dumps(summary, indent=2))

    missing = [k for k, v in summary.items() if k in ("server", "project", "email") and not v]
    if missing:
        print(f"WARNING: missing expected fields: {', '.join(missing)}")
        return 1

    print("OK: Jira dashboard config appears to be wired into JiraNotifier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
