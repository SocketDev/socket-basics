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
    all_clear_calls: list[tuple[int, set[str]]] = []
    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(notifier, '_reconcile_pr_labels', lambda pr_number, labels: reconciled.append((pr_number, labels)) or True)
    monkeypatch.setattr(
        notifier,
        '_replace_existing_sections_with_all_clear',
        lambda pr_number, section_types=None: all_clear_calls.append((pr_number, section_types)) or None,
    )

    notifier.notify({'notifications': []})

    assert reconciled == [(123, [])]
    assert all_clear_calls == [(123, set())]


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

    notifier.notify(
        {
            'notifications': [],
            'components': [
                {
                    'alerts': [
                        {
                            'generatedBy': 'opengrep-javascript',
                            'subType': 'sast-javascript',
                            'action': 'ignore',
                        }
                    ]
                }
            ],
        }
    )

    assert len(updated_bodies) == 1
    assert 'Socket Basics found no active findings in the latest run.' in updated_bodies[0]
    assert '<!-- sast-javascript start -->' in updated_bodies[0]


def test_notify_empty_sast_notifications_do_not_rewrite_unrelated_sections(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': True,
        }
    )

    sast_comment = """<!-- sast-javascript start -->
## <img src="https://example.test/logo.png" width="24" height="24"> Socket SAST JavaScript

### Summary
🟡 Medium: 1
<!-- sast-javascript end -->"""
    tier1_comment = """<!-- socket-tier1 start -->
## <img src="https://example.test/logo.png" width="24" height="24"> Socket Security Tier 1

### Summary
🟠 High: 2
<!-- socket-tier1 end -->"""
    updated_comments: list[tuple[int, str]] = []

    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(notifier, '_reconcile_pr_labels', lambda pr_number, labels: True)
    monkeypatch.setattr(
        notifier,
        '_get_pr_comments',
        lambda pr_number: [
            {'id': 99, 'body': sast_comment},
            {'id': 100, 'body': tier1_comment},
        ],
    )
    monkeypatch.setattr(
        notifier,
        '_update_comment',
        lambda pr_number, comment_id, body: updated_comments.append((comment_id, body)) or True,
    )

    notifier.notify(
        {
            'notifications': [],
            'components': [
                {
                    'alerts': [
                        {
                            'generatedBy': 'opengrep-javascript',
                            'subType': 'sast-javascript',
                            'action': 'ignore',
                        }
                    ]
                }
            ],
        }
    )

    assert len(updated_comments) == 1
    assert updated_comments[0][0] == 99
    assert '<!-- sast-javascript start -->' in updated_comments[0][1]
    assert 'Socket Basics found no active findings in the latest run.' in updated_comments[0][1]
    assert '<!-- socket-tier1 start -->' not in updated_comments[0][1]


def test_notify_rewrites_all_clear_even_when_pr_labels_are_disabled(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': False,
        }
    )

    comment_body = """<!-- sast-javascript start -->
## Socket SAST JavaScript

### Summary
🟠 High: 1
<!-- sast-javascript end -->"""
    updated_bodies: list[str] = []

    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(
        notifier,
        '_reconcile_pr_labels',
        lambda pr_number, labels: (_ for _ in ()).throw(AssertionError('labels are disabled')),
    )
    monkeypatch.setattr(notifier, '_get_pr_comments', lambda pr_number: [{'id': 99, 'body': comment_body}])
    monkeypatch.setattr(
        notifier,
        '_update_comment',
        lambda pr_number, comment_id, body: updated_bodies.append(body) or True,
    )

    notifier.notify(
        {
            'notifications': [],
            'components': [
                {
                    'alerts': [
                        {
                            'generatedBy': 'opengrep-javascript',
                            'subType': 'sast-javascript',
                            'action': 'ignore',
                        }
                    ]
                }
            ],
        }
    )

    assert len(updated_bodies) == 1
    assert 'Socket Basics found no active findings in the latest run.' in updated_bodies[0]
    assert '<!-- sast-javascript start -->' in updated_bodies[0]


def test_notify_zero_alert_component_metadata_rewrites_matching_section(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': True,
        }
    )

    comment_body = """<!-- sast-javascript start -->
## Socket SAST JavaScript

### Summary
🟠 High: 1
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

    notifier.notify(
        {
            'notifications': [],
            'components': [
                {
                    'id': 'src/index.js',
                    'subPath': 'sast-javascript',
                    'alerts': [],
                }
            ],
        }
    )

    assert len(updated_bodies) == 1
    assert 'Socket Basics found no active findings in the latest run.' in updated_bodies[0]
    assert '<!-- sast-javascript start -->' in updated_bodies[0]


def test_notify_zero_alert_enabled_sast_config_rewrites_matching_section(monkeypatch):
    notifier = GithubPRNotifier(
        {
            'repository': 'SocketDev/socket-basics',
            'pr_labels_enabled': True,
        }
    )
    notifier.app_config = {'javascript_sast_enabled': True}

    comment_body = """<!-- sast-javascript start -->
## Socket SAST JavaScript

### Summary
🟠 High: 1
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

    notifier.notify({'notifications': [], 'components': []})

    assert len(updated_bodies) == 1
    assert 'Socket Basics found no active findings in the latest run.' in updated_bodies[0]
    assert '<!-- sast-javascript start -->' in updated_bodies[0]


# ---------------------------------------------------------------------------
# pr_comment_enabled: suppress the PR comment without suppressing the scan
# ---------------------------------------------------------------------------

def _suppression_notifier(monkeypatch, **params):
    """A notifier whose every GitHub write is recorded instead of performed."""
    notifier = GithubPRNotifier({'repository': 'SocketDev/socket-basics', **params})
    calls = {'posted': [], 'updated': [], 'labels': []}

    monkeypatch.setattr(notifier, '_get_pr_number', lambda: 123)
    monkeypatch.setattr(notifier, '_get_pr_comments', lambda pr_number: [])
    monkeypatch.setattr(
        notifier, '_post_comment', lambda pr_number, body: calls['posted'].append(body) or True
    )
    monkeypatch.setattr(
        notifier,
        '_update_comment',
        lambda pr_number, comment_id, body: calls['updated'].append(body) or True,
    )
    monkeypatch.setattr(
        notifier,
        '_reconcile_pr_labels',
        lambda pr_number, labels: calls['labels'].append(labels) or True,
    )
    return notifier, calls


_FINDING = {
    'title': 'Socket SAST JavaScript',
    'content': '<!-- sast-javascript start -->\n🔴 Critical: 1\n<!-- sast-javascript end -->',
}


def test_notify_posts_comment_by_default(monkeypatch):
    notifier, calls = _suppression_notifier(monkeypatch)

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert len(calls['posted']) == 1


def test_notify_posts_no_comment_when_pr_comment_disabled(monkeypatch):
    notifier, calls = _suppression_notifier(monkeypatch, pr_comment_enabled=False)

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert calls['posted'] == []
    assert calls['updated'] == []


def test_notify_posts_no_all_clear_comment_when_pr_comment_disabled(monkeypatch):
    """An empty run must not rewrite an existing comment into "no findings"."""
    existing = """<!-- sast-javascript start -->
## Socket SAST JavaScript

### Summary
🟠 High: 1
<!-- sast-javascript end -->"""

    notifier, calls = _suppression_notifier(monkeypatch, pr_comment_enabled=False)
    notifier.app_config = {'javascript_sast_enabled': True}
    monkeypatch.setattr(notifier, '_get_pr_comments', lambda pr_number: [{'id': 99, 'body': existing}])

    notifier.notify({'notifications': [], 'components': []})

    assert calls['posted'] == []
    assert calls['updated'] == []


def test_notify_still_applies_labels_when_pr_comment_disabled(monkeypatch):
    """Comments and labels are independent switches."""
    notifier, calls = _suppression_notifier(
        monkeypatch, pr_comment_enabled=False, pr_labels_enabled=True
    )

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert calls['labels'] == [['security: critical']]


def test_notify_skips_labels_when_both_switches_are_off(monkeypatch):
    notifier, calls = _suppression_notifier(
        monkeypatch, pr_comment_enabled=False, pr_labels_enabled=False
    )

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert calls['posted'] == []
    assert calls['labels'] == []


def test_notify_honors_string_false_from_dashboard_config(monkeypatch):
    """A Socket dashboard config supplies flags as strings, not booleans."""
    notifier, calls = _suppression_notifier(monkeypatch, pr_comment_enabled='false')

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert calls['posted'] == []


def test_notify_honors_string_false_for_labels(monkeypatch):
    """pr_labels_enabled needs the same string handling as pr_comment_enabled."""
    notifier, calls = _suppression_notifier(
        monkeypatch, pr_comment_enabled='false', pr_labels_enabled='false'
    )

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert calls['posted'] == []
    assert calls['labels'] == []


def test_notify_string_false_labels_are_skipped_on_the_normal_path(monkeypatch):
    """Not just the suppression branch -- the ordinary posting path too."""
    notifier, calls = _suppression_notifier(monkeypatch, pr_labels_enabled='false')

    notifier.notify({'notifications': [_FINDING], 'components': []})

    assert len(calls['posted']) == 1
    assert calls['labels'] == []


def test_notify_leaves_facts_untouched_when_pr_comment_disabled(monkeypatch):
    """Suppression is comment-only: the uploaded facts payload is not altered."""
    notifier, _calls = _suppression_notifier(monkeypatch, pr_comment_enabled=False)
    facts = {
        'notifications': [_FINDING],
        'components': [{'id': 'src/index.js', 'alerts': [{'severity': 'critical'}]}],
        'full_scan_html_url': 'https://socket.dev/dashboard/scan/12345',
    }

    notifier.notify(facts)

    assert facts['components'] == [{'id': 'src/index.js', 'alerts': [{'severity': 'critical'}]}]
    assert facts['full_scan_html_url'] == 'https://socket.dev/dashboard/scan/12345'
