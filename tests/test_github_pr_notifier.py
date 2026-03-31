from socket_basics.core.notification.github_pr_notifier import GithubPRNotifier


def _notification(summary: str) -> dict:
    return {'title': 'Socket SAST JavaScript', 'content': summary}


def test_determine_pr_labels_prefers_highest_current_severity():
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_label_critical': 'security: critical',
            'pr_label_high': 'security: high',
            'pr_label_medium': 'security: medium',
            'pr_label_low': 'security: low',
        }
    )

    labels = notifier._determine_pr_labels(
        [_notification('Critical: 0 | High: 1 | Medium: 2 | Low: 3')]
    )

    assert labels == ['security: high']


def test_determine_pr_labels_supports_low_severity():
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_label_low': 'security: low',
        }
    )

    labels = notifier._determine_pr_labels(
        [_notification('Critical: 0 | High: 0 | Medium: 0 | Low: 2')]
    )

    assert labels == ['security: low']


def test_reconcile_pr_labels_replaces_stale_managed_severity(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_label_critical': 'security: critical',
            'pr_label_high': 'security: high',
            'pr_label_medium': 'security: medium',
            'pr_label_low': 'security: low',
        }
    )

    removed: list[str] = []
    added: list[str] = []
    ensured: list[str] = []

    monkeypatch.setattr(notifier, '_get_current_pr_label_names', lambda pr_number: ['security: critical', 'team: backend'])
    monkeypatch.setattr(notifier, '_remove_pr_label', lambda pr_number, label: removed.append(label) or True)
    monkeypatch.setattr(notifier, '_ensure_pr_labels_exist', lambda labels: ensured.extend(labels))
    monkeypatch.setattr(notifier, '_add_pr_labels', lambda pr_number, labels: added.extend(labels) or True)

    success = notifier._reconcile_pr_labels(123, ['security: medium'])

    assert success is True
    assert removed == ['security: critical']
    assert ensured == ['security: medium']
    assert added == ['security: medium']


def test_reconcile_pr_labels_clears_managed_labels_when_none_desired(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_label_critical': 'security: critical',
            'pr_label_high': 'security: high',
            'pr_label_medium': 'security: medium',
            'pr_label_low': 'security: low',
        }
    )

    removed: list[str] = []
    monkeypatch.setattr(notifier, '_get_current_pr_label_names', lambda pr_number: ['security: high', 'docs'])
    monkeypatch.setattr(notifier, '_remove_pr_label', lambda pr_number, label: removed.append(label) or True)
    monkeypatch.setattr(notifier, '_ensure_pr_labels_exist', lambda labels: (_ for _ in ()).throw(AssertionError('should not ensure labels')))
    monkeypatch.setattr(notifier, '_add_pr_labels', lambda pr_number, labels: (_ for _ in ()).throw(AssertionError('should not add labels')))

    success = notifier._reconcile_pr_labels(123, [])

    assert success is True
    assert removed == ['security: high']
