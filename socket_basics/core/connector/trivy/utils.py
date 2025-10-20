import logging
from pathlib import Path
import yaml

logger = logging.getLogger("trivy-scanner")


def get_notifier_result_limit(notifier_name: str) -> int:
    """Get the result limit for a specific notifier from notifications config.
    
    Args:
        notifier_name: Name of the notifier (e.g., 'jira', 'slack', 'github_pr')
        
    Returns:
        Maximum number of results for this notifier
    """
    try:
        # Try to load notifications.yaml to get the limit
        base_dir = Path(__file__).parent.parent.parent
        notifications_path = base_dir / "notifications.yaml"
        
        if notifications_path.exists():
            with open(notifications_path, 'r') as f:
                config = yaml.safe_load(f)
                result_limits = config.get('settings', {}).get('result_limits', {})
                return result_limits.get(notifier_name, result_limits.get('default', 50))
    except Exception as e:
        logger.debug(f"Could not load {notifier_name} result limit from config: {e}")
    
    # Fallback defaults by notifier type
    defaults = {
        'jira': 30,
        'slack': 50,
        'msteams': 50,
        'github_pr': 100,
        'webhook': 100,
        'console': 1000,
        'json': 10000,
        'sumologic': 500,
        'ms_sentinel': 500
    }
    return defaults.get(notifier_name, 50)

