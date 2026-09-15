from socket_basics.core.notification.github_pr_notifier import GithubPRNotifier
from socket_basics.core.notification.manager import NotificationManager


def _base_cfg():
    return {
        "notifiers": {
            "github_pr": {
                "module_path": "socket_basics.core.notification.github_pr_notifier",
                "class": "GithubPRNotifier",
                "parameters": [
                    {"name": "github_token", "env_variable": "GITHUB_TOKEN", "type": "str"},
                ],
            }
        }
    }


def _clear_token_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)


def test_github_pr_notifier_reads_token_from_params(monkeypatch):
    """github_token param from dashboard config should populate self.token"""
    _clear_token_env(monkeypatch)
    n = GithubPRNotifier({"github_token": "ghp_from_params"})
    assert n.token == "ghp_from_params"


def test_github_pr_notifier_token_is_none_without_config(monkeypatch):
    """Without any config or env var, token should be falsy"""
    _clear_token_env(monkeypatch)
    n = GithubPRNotifier({})
    assert not n.token


def test_github_pr_notifier_falls_back_to_env_var(monkeypatch):
    """GITHUB_TOKEN env var should work as fallback when params empty"""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
    n = GithubPRNotifier({})
    assert n.token == "ghp_from_env"


def test_github_pr_notifier_params_take_precedence_over_env(monkeypatch):
    """Dashboard config (params) should take precedence over env var"""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
    n = GithubPRNotifier({"github_token": "ghp_from_dashboard"})
    assert n.token == "ghp_from_dashboard"


def test_github_pr_notifier_accepts_legacy_token_key(monkeypatch):
    """A directly constructed notifier may still pass token"""
    _clear_token_env(monkeypatch)
    n = GithubPRNotifier({"token": "ghp_legacy"})
    assert n.token == "ghp_legacy"


def test_github_pr_enabled_via_app_config(monkeypatch):
    """Notifier should load and receive the token when github_token is in app_config"""
    _clear_token_env(monkeypatch)

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"github_token": "ghp_from_dashboard"})
    nm.load_from_config()

    notifier = next(n for n in nm.notifiers if getattr(n, "name", "") == "github_pr")
    assert notifier.token == "ghp_from_dashboard"


def test_github_pr_enabled_via_env_var(monkeypatch):
    """Notifier should load and receive the token when GITHUB_TOKEN is set"""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={})
    nm.load_from_config()

    notifier = next(n for n in nm.notifiers if getattr(n, "name", "") == "github_pr")
    assert notifier.token == "ghp_from_env"


def test_github_pr_app_config_precedence_over_env(monkeypatch):
    """app_config github_token should take precedence over env var in manager flow"""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")

    cfg = _base_cfg()
    nm = NotificationManager(cfg, app_config={"github_token": "ghp_from_dashboard"})
    nm.load_from_config()

    notifier = next(n for n in nm.notifiers if getattr(n, "name", "") == "github_pr")
    assert notifier.token == "ghp_from_dashboard"
