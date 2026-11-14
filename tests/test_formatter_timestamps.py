import json
from datetime import datetime, timedelta

import pytest

from socket_basics.core.formatters.sentinel import SentinelFormatter
from socket_basics.core.formatters.sumologic import SumologicFormatter
from socket_basics.core.formatters.webhook import WebhookFormatter


@pytest.mark.parametrize(
    "formatter,key",
    [
        (SentinelFormatter, "TimeGenerated"),
        (SumologicFormatter, "timestamp"),
        (WebhookFormatter, "timestamp"),
    ],
)
@pytest.mark.parametrize("findings", [[], [{"title": "example", "severity": "high"}]])
def test_notification_timestamps_keep_a_single_utc_designator(formatter, key, findings):
    payload = json.loads(formatter().format_findings(findings))
    stamp = payload[key]
    assert stamp.endswith("Z")
    assert "+00:00" not in stamp
    assert datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() == timedelta(0)
