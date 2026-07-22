from socket_basics.core.notification.manager import NotificationManager


class _DummyGithubPrNotifier:
    name = "github_pr"

    def __init__(self):
        self.payloads = []

    def notify(self, facts):
        self.payloads.append(facts)


def test_notify_all_passes_empty_notifications_to_github_pr_for_all_clear():
    notifier = _DummyGithubPrNotifier()
    nm = NotificationManager({}, app_config={"repo": "SocketDev/socket-basics"})
    nm.notifiers = [notifier]

    nm.notify_all({"components": [], "notifications": {}})

    assert len(notifier.payloads) == 1
    assert notifier.payloads[0]["notifications"] == []
