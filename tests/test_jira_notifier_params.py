from socket_basics.core.notification.jira_notifier import JiraNotifier
from socket_basics.core.config import normalize_api_config


def test_jira_notifier_reads_new_param_names():
    n = JiraNotifier(
        {
            "jira_url": "https://acme.atlassian.net",
            "jira_project": "SEC",
            "jira_email": "bot@acme.example",
            "jira_api_token": "token123",
        }
    )
    assert n.server == "https://acme.atlassian.net"
    assert n.project == "SEC"
    assert n.email == "bot@acme.example"
    assert n.api_token == "token123"


def test_jira_notifier_falls_back_to_auth_dict():
    n = JiraNotifier(
        {
            "jira_url": "https://acme.atlassian.net",
            "jira_project": "SEC",
            "auth": {"email": "auth@acme.example", "api_token": "auth-token"},
        }
    )
    assert n.email == "auth@acme.example"
    assert n.api_token == "auth-token"


def test_normalize_api_config_maps_jira_keys():
    normalized = normalize_api_config(
        {
            "jiraUrl": "https://acme.atlassian.net",
            "jiraProject": "SEC",
            "jiraEmail": "bot@acme.example",
            "jiraApiToken": "token123",
        }
    )
    assert normalized["jira_url"] == "https://acme.atlassian.net"
    assert normalized["jira_project"] == "SEC"
    assert normalized["jira_email"] == "bot@acme.example"
    assert normalized["jira_api_token"] == "token123"
