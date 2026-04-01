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


def test_notify_reconciles_labels_even_when_notifications_are_empty(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': True,
        }
    )

    reconciled: list[tuple[int, list[str]]] = []
    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(notifier, '_reconcile_pr_labels', lambda pr_number, labels: reconciled.append((pr_number, labels)) or True)

    notifier.notify({'notifications': []})

    assert reconciled == [(123, [])]


def test_notify_rewrites_existing_section_to_all_clear_when_notifications_are_empty(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': True,
        }
    )

    comment_body = """<!-- sast-javascript start -->
## <img src="https://example.test/logo.png" width="24" height="24"> Socket SAST JavaScript

### Summary
🟡 Medium: 1
<!-- sast-javascript end -->"""
    updated_bodies: list[str] = []

    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(notifier, '_reconcile_pr_labels', lambda pr_number, labels: True)
    monkeypatch.setattr(notifier, '_get_pr_comments', lambda pr_number: [{'id': 99, 'body': comment_body}])
    monkeypatch.setattr(
        notifier,
        '_update_comment',
        lambda pr_number, comment_id, body: updated_bodies.append(body) or True,
    )

    notifier.notify({'notifications': []})

    assert len(updated_bodies) == 1
    assert 'Socket Basics found no active findings in the latest run.' in updated_bodies[0]
    assert '<!-- sast-javascript start -->' in updated_bodies[0]
