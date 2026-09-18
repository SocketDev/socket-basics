"""An alert must locate a credential without reproducing it.

Every field a connector puts on an alert is written to the facts file in the
scanned workspace, uploaded to Socket, rendered in the dashboard, and forwarded
to the configured notifiers. A snippet copied verbatim from the source line
therefore ends up in all of those places, which for a hardcoded-credential
finding means the credential itself does.

Masking happens where the alert is built, so these tests assert on the alert
rather than on any single destination: the notifiers all read
``props.codeSnippet`` and inherit whatever is there.
"""

import glob
import json
import re
from pathlib import Path

import pytest
import yaml

from socket_basics.core.utils.redaction import (
    is_credential_finding,
    mask_value,
    redact_dataflow_trace,
    redact_literals,
    redact_message,
    redact_snippet,
    scrub_tokens,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "socket_basics" / "rules"


def _sample(prefix: str, body: str) -> str:
    """Assemble a stand-in credential from its prefix and body.

    The values below are not real -- each is a published example or a
    syntactically valid value of the right shape. They are still built at
    runtime rather than written as literals, because the formats under test are
    exactly the ones a scanner walking this repository looks for, and a literal
    here would be reported as a finding in its own right. Splitting the string
    keeps that quiet without weakening what the test asserts.
    """
    return prefix + body


AWS_KEY_ID = _sample("AKIA", "IOSFODNN7EXAMPLE")
GITHUB_TOKEN = _sample("ghp_", "16C7e42F292c6912E7710c838347Ae178B4a")
GITHUB_PAT = _sample("github_pat_", "11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789")
STRIPE_KEY = _sample("sk_live_", "51QwErTyUiOpAsDfGhJkLzXc")
SLACK_TOKEN = _sample("xoxb-", "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")
GOOGLE_KEY = _sample("AIza", "SyD-1234567890abcdefghijklmnopqrstu")
NPM_TOKEN = _sample("npm_", "abcdefghijklmnopqrstuvwxyz0123456789")
PYPI_TOKEN = _sample("pypi-", "AgEIcHlwaS5vcmcCJDAwMDAwMDAw")
JWT = _sample(
    "eyJhbGciOiJIUzI1NiJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
)

SAMPLE_TOKENS = [
    AWS_KEY_ID,
    GITHUB_TOKEN,
    GITHUB_PAT,
    STRIPE_KEY,
    SLACK_TOKEN,
    GOOGLE_KEY,
    NPM_TOKEN,
    PYPI_TOKEN,
]


class TestMaskValue:
    def test_long_values_keep_an_identifying_head_and_tail(self):
        masked = mask_value(STRIPE_KEY)
        assert masked.startswith("sk_l")
        assert masked.endswith("LzXc")
        assert "51QwErTyUiOpAsDfGhJk" not in masked

    def test_short_values_are_masked_completely(self):
        # A revealed head and tail would be most of a short credential, so
        # nothing is kept.
        assert mask_value("SuperSecret123!") == "*" * len("SuperSecret123!")
        assert mask_value("hunter2") == "*******"

    def test_masked_length_matches_the_original(self):
        for value in ("a", "short", STRIPE_KEY):
            assert len(mask_value(value)) == len(value)

    def test_empty_and_non_string_values_are_handled(self):
        assert mask_value("") == ""
        assert mask_value(None) == ""
        assert mask_value(12345678901234567890) == "1234************7890"


class TestScrubTokens:
    @pytest.mark.parametrize("token", SAMPLE_TOKENS)
    def test_known_credential_formats_never_survive(self, token):
        text = f"value = connect({token})"
        assert token not in scrub_tokens(text)

    def test_pem_private_key_bodies_are_replaced(self):
        body = _sample(
            "MIIEowIBAAKCAQEAwJz9Fq3n0pQ7bTvXyZ1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT\n",
            "uVwXyZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
        )
        marker = _sample("-----BEGIN RSA PRIVATE", " KEY-----")
        pem = f"{marker}\n{body}\n{marker.replace('BEGIN', 'END')}"
        scrubbed = scrub_tokens(pem)
        assert body.split("\n")[0] not in scrubbed
        assert scrubbed.startswith(marker)
        assert scrubbed.endswith(marker.replace("BEGIN", "END"))

    def test_jwt_payloads_are_masked(self):
        # The payload segment carries the claims, so it is the part that matters.
        payload = JWT.split(".")[1]
        assert payload not in scrub_tokens(f"const t = '{JWT}';")

    def test_credentials_in_a_url_authority_are_masked(self):
        password = _sample("Tr0ub4dor", "&3xyz")
        scrubbed = scrub_tokens(f"postgres://admin:{password}@db.internal:5432/app")
        assert password not in scrubbed
        # The host stays readable so the finding still points somewhere.
        assert "db.internal:5432/app" in scrubbed

    def test_url_password_is_masked_when_it_matches_the_username(self):
        scrubbed = scrub_tokens("postgres://admin:admin@db.internal/app")
        assert scrubbed.startswith("postgres://admin:")
        assert ":admin@" not in scrubbed

    def test_ordinary_code_is_left_alone(self):
        for snippet in (
            "eval(rawConfigStr)",
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
            "app.use(express.static('public'))",
            "if len(password) < 8:",
        ):
            assert scrub_tokens(snippet) == snippet


class TestRedactLiterals:
    def test_the_assignment_target_survives_but_the_value_does_not(self):
        redacted = redact_literals(f'STRIPE_SECRET_KEY = "{STRIPE_KEY}"')
        assert redacted.startswith('STRIPE_SECRET_KEY = "')
        assert "51QwErTyUiOpAsDfGhJk" not in redacted

    def test_every_quote_style_is_covered(self):
        assert "SuperSecret123!" not in redact_literals(
            "const DB_PASSWORD = 'SuperSecret123!';"
        )
        assert "SuperSecret123!" not in redact_literals(
            "const DB_PASSWORD = `SuperSecret123!`;"
        )
        assert "SuperSecret123!" not in redact_literals(
            'DB_PASSWORD = "SuperSecret123!"'
        )

    def test_escaped_quotes_inside_a_literal_do_not_end_it(self):
        redacted = redact_literals(r'key = "abc\"def SuperSecret123!"')
        assert "SuperSecret123!" not in redacted

    def test_multi_character_operators_keep_their_syntax(self):
        """A quoted value must reach the literal pass whatever precedes it.

        Matching only the first character of ``:=`` or ``==`` leaves the rest of
        the operator heading the value, which stops looking quoted and sends the
        line to the unquoted branch -- which stars out the operator and quotes
        the literal pass exists to keep. ``go-hardcoded-credentials`` matches
        ``$VAR := "..."``, so this is a shape the bundled rules produce.
        """
        for line, prefix in (
            ('apiKey := "SuperSecret123!"', 'apiKey := "'),
            ('if password == "SuperSecret123!" {', 'if password == "'),
            ('if password != "SuperSecret123!" {', 'if password != "'),
        ):
            redacted = redact_literals(line)
            assert "SuperSecret123!" not in redacted
            assert redacted.startswith(prefix), redacted

    def test_a_scope_operator_is_not_read_as_an_assignment(self):
        # ``::`` is not an assignment, so the line keeps its shape and the
        # literal pass handles the value.
        redacted = redact_literals('let cfg = Config::new("SuperSecret123!");')
        assert "SuperSecret123!" not in redacted

    def test_unquoted_assignments_fall_back_to_masking_the_value(self):
        redacted = redact_literals("password: SuperSecret123!")
        assert "SuperSecret123!" not in redacted
        assert redacted.startswith("password: ")

    def test_quoted_text_does_not_skip_an_unquoted_value(self):
        redacted = redact_literals('password: hunter2 # "temporary"')
        assert "hunter2" not in redacted
        assert redacted.startswith("password: ")

    def test_each_line_uses_the_appropriate_redaction(self):
        redacted = redact_literals(
            'credentials:\n  user: "admin"\n  password: hunter2'
        )
        assert "admin" not in redacted
        assert "hunter2" not in redacted

    def test_empty_literals_are_left_as_they_are(self):
        assert redact_literals('password = ""') == 'password = ""'


class TestCredentialRuleSelection:
    @pytest.mark.parametrize(
        "rule_id",
        [
            "python-hardcoded-secret",
            "js-hardcoded-secret",
            "java-hardcoded-credentials",
            "go-hardcoded-credentials",
            "swift-hardcoded-secrets",
            "python-hardcoded-password-default",
            "js-default-credentials",
            "js-weak-jwt-secret",
            "python-plain-text-password",
        ],
    )
    def test_hardcoded_credential_rules_are_selected(self, rule_id):
        assert is_credential_finding(rule_id, {})

    @pytest.mark.parametrize(
        "rule_id",
        [
            # The match is a literal address, and masking it would remove the
            # reason the finding was raised.
            "python-hardcoded-ip",
            "java-hardcoded-ip",
            # These match a length comparison, not a credential.
            "python-weak-password-validation",
            "js-weak-password-validation",
            "python-sql-injection-format",
            "js-eval-usage",
        ],
    )
    def test_rules_whose_match_is_not_a_credential_are_not_selected(self, rule_id):
        assert not is_credential_finding(rule_id, {})

    def test_rule_metadata_overrides_the_name(self):
        assert is_credential_finding("custom-vault-lookup", {"redact": True})
        assert is_credential_finding("custom-vault-lookup", {"redact": "yes"})
        assert not is_credential_finding("python-hardcoded-secret", {"redact": False})

    def test_every_bundled_hardcoded_credential_rule_is_covered(self):
        """The bundled rules are the contract, so check them rather than a list.

        A new language file lands with the same ``*-hardcoded-secrets`` naming
        as the existing fifteen; this fails if one arrives that the selector
        does not recognize.
        """
        uncovered = []
        for rule_file in sorted(glob.glob(str(RULES_DIR / "*.yml"))):
            for rule in (yaml.safe_load(Path(rule_file).read_text()) or {}).get("rules", []):
                rule_id = rule.get("id", "")
                if not re.search(r"hardcoded-(secret|credential|password|key|token)", rule_id):
                    continue
                if not is_credential_finding(rule_id, rule.get("metadata") or {}):
                    uncovered.append(rule_id)
        assert uncovered == []


class TestRedactSnippet:
    def test_a_credential_finding_masks_the_literal(self):
        redacted = redact_snippet(
            'DB_PASSWORD = "SuperSecret123!"', credential_finding=True
        )
        assert "SuperSecret123!" not in redacted
        assert "DB_PASSWORD" in redacted

    def test_a_non_credential_finding_keeps_its_code_readable(self):
        snippet = "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
        assert redact_snippet(snippet, credential_finding=False) == snippet

    def test_a_non_credential_finding_still_loses_a_recognizable_token(self):
        # The rule is about logging, but the line happens to carry a real key.
        snippet = f"console.log('key', '{AWS_KEY_ID}')"
        redacted = redact_snippet(snippet, credential_finding=False)
        assert AWS_KEY_ID not in redacted
        assert "console.log" in redacted


class TestRedactMessage:
    def test_interpolated_metavariables_are_masked_for_credential_findings(self):
        secret = "SuperSecret123!"
        redacted = redact_message(
            f"Hardcoded credential {secret} assigned to database_password",
            {
                "$VALUE": {"abstract_content": secret},
                "$VAR": {"abstract_content": "database_password"},
            },
            credential_finding=True,
        )
        assert secret not in redacted
        assert "database_password" not in redacted
        assert redacted.startswith("Hardcoded credential ")

    def test_known_tokens_are_scrubbed_from_every_message(self):
        assert AWS_KEY_ID not in redact_message(f"Logged value: {AWS_KEY_ID}")

    def test_a_short_bound_value_does_not_mangle_the_rest_of_the_message(self):
        """The replace is by value, so a short one is also an ordinary substring.

        Masking every occurrence would rewrite words that merely contain it.
        The credential still has to be masked, so the replace is anchored rather
        than skipped.
        """
        redacted = redact_message(
            "secret a is bad", {"$X": {"abstract_content": "a"}}, credential_finding=True
        )
        assert redacted == "secret * is bad"

    def test_a_short_bound_value_is_still_masked(self):
        for message, expected in (
            ("password admin is a bad default", "password ***** is a bad default"),
            ("key is at the end: admin", "key is at the end: *****"),
        ):
            assert (
                redact_message(
                    message, {"$P": {"abstract_content": "admin"}}, credential_finding=True
                )
                == expected
            )

    def test_a_long_bound_value_is_masked_wherever_it_appears(self):
        redacted = redact_message(
            'Hardcoded secret in DB_PASSWORD = "SuperSecret123!"',
            {
                "$VAR": {"abstract_content": "DB_PASSWORD"},
                "$V": {"abstract_content": "SuperSecret123!"},
            },
            credential_finding=True,
        )
        assert "SuperSecret123!" not in redacted
        assert "DB_PASSWORD" not in redacted

    def test_a_non_credential_finding_keeps_its_message(self):
        message = "Use of eval() on untrusted input"
        assert redact_message(message, {"$X": {"abstract_content": "eval"}}) == message


class TestPasswordLogicRules:
    """``python-plain-text-password`` matches two shapes and needs both served.

    Its handling patterns assign request input to a password field, where the
    expression is the finding. Its comparison pattern can bind a hardcoded
    string, and no ``hardcoded-*`` rule covers that shape, so the value has to
    be masked here or it is not masked at all.
    """

    def test_a_password_handling_snippet_keeps_its_expression(self):
        redacted = redact_snippet(
            "user.password = request.form.get('password')", credential_finding=True
        )
        assert redacted.startswith("user.password = request.form.get(")
        assert redacted.endswith(")")

    def test_a_hardcoded_comparison_value_is_masked(self):
        redacted = redact_snippet(
            'if user.password == "hunter2":', credential_finding=True
        )
        assert "hunter2" not in redacted
        assert redacted.startswith('if user.password == "')

    def test_a_bare_value_with_a_trailing_comment_is_masked_whole(self):
        # No call, so this stays on the unquoted path: measuring the value plus
        # the comment could otherwise partially reveal a short credential.
        redacted = redact_snippet('password: hunter2 # see "notes"', credential_finding=True)
        assert "hunter2" not in redacted
        assert "notes" not in redacted

    def test_a_literal_argument_to_a_call_is_still_masked(self):
        redacted = redact_snippet(
            "password = get_secret('default_pw')", credential_finding=True
        )
        assert "default_pw" not in redacted
        assert redacted.startswith("password = get_secret(")


class TestRedactDataflowTrace:
    def test_a_credential_finding_masks_literals_in_its_trace(self):
        """A trace step is a source line, so it gets the snippet's treatment.

        ``scrub_tokens`` alone would keep a generic password, which the
        vendor-format patterns do not recognize.
        """
        trace = {
            "source": {"content": 'password = "SuperSecret123!"', "file": "a.py", "line": 1},
            "intermediates": [
                {"content": 'tmp = "SuperSecret123!"', "file": "a.py", "line": 2}
            ],
            "sink": {"content": 'connect(password="SuperSecret123!")', "file": "a.py", "line": 3},
        }
        serialized = json.dumps(redact_dataflow_trace(trace, credential_finding=True))
        assert "SuperSecret123!" not in serialized
        assert '"line": 3' in serialized

    def test_a_non_credential_finding_keeps_its_trace_readable(self):
        trace = {
            "source": {"content": "user_id = request.args.get('id')", "file": "a.py", "line": 1},
            "sink": {"content": "cursor.execute(query)", "file": "a.py", "line": 2},
        }
        redacted = redact_dataflow_trace(trace)
        assert redacted["source"]["content"] == "user_id = request.args.get('id')"
        assert redacted["sink"]["content"] == "cursor.execute(query)"

    def test_trace_steps_are_scrubbed(self):
        trace = {
            "source": {"content": f"key = '{AWS_KEY_ID}'", "file": "a.py", "line": 1},
            "intermediates": [
                {"content": f"tmp = '{GITHUB_TOKEN}'", "file": "a.py", "line": 2}
            ],
            "sink": {"content": "requests.get(url, headers={'k': key})", "file": "a.py", "line": 3},
        }
        serialized = json.dumps(redact_dataflow_trace(trace))
        assert AWS_KEY_ID not in serialized
        assert GITHUB_TOKEN not in serialized
        # Locations survive, which is what makes the trace useful.
        assert '"line": 3' in serialized

    def test_a_trace_of_an_unexpected_shape_is_returned_unchanged(self):
        assert redact_dataflow_trace(None) is None
        assert redact_dataflow_trace("not a trace") == "not a trace"


class TestConnectorOutput:
    """The masking has to survive the trip through the connectors."""

    def test_opengrep_alerts_carry_no_credential(self, tmp_path):
        from socket_basics.core.connector.opengrep import OpenGrepScanner

        raw = {
            "results": [
                {
                    "check_id": "socket_basics.rules.python-hardcoded-secret",
                    "path": str(tmp_path / "config.py"),
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {
                        "severity": "ERROR",
                        "message": f"Hardcoded credential detected: {STRIPE_KEY}",
                        "lines": f'STRIPE_SECRET_KEY = "{STRIPE_KEY}"',
                        "metavars": {
                            "$VALUE": {"abstract_content": STRIPE_KEY},
                        },
                        "metadata": {"cwe": "CWE-798", "confidence": "medium"},
                    },
                }
            ]
        }

        scanner = OpenGrepScanner.__new__(OpenGrepScanner)
        scanner.config = _StubConfig(tmp_path)
        scanner.allowed_severities = {"critical", "high", "medium", "low"}
        components = scanner._convert_to_socket_facts(raw)

        serialized = json.dumps(components)
        assert STRIPE_KEY not in serialized
        assert "python-hardcoded-secret" in serialized

    def test_trufflehog_alerts_carry_no_credential(self, tmp_path):
        from socket_basics.core.connector.trufflehog import TruffleHogScanner

        # TruffleHog reports the match verbatim in Raw and leaves Redacted
        # empty for most detectors, so the connector cannot pass either through.
        finding = {
            "DetectorName": "Stripe",
            "Verified": False,
            "Raw": STRIPE_KEY,
            "Redacted": "",
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": str(tmp_path / "config.py"), "line": 3}}
            },
        }

        scanner = TruffleHogScanner.__new__(TruffleHogScanner)
        scanner.config = _StubConfig(tmp_path)
        alert = scanner._create_alert(finding)

        serialized = json.dumps(alert)
        assert STRIPE_KEY not in serialized
        assert alert["props"]["lineNumber"] == 3

    def test_a_short_secret_is_not_partly_revealed(self, tmp_path):
        from socket_basics.core.connector.trufflehog import TruffleHogScanner

        scanner = TruffleHogScanner.__new__(TruffleHogScanner)
        scanner.config = _StubConfig(tmp_path)
        alert = scanner._create_alert(
            {
                "DetectorName": "Generic",
                "Verified": False,
                "Raw": "SuperSecret123!",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": str(tmp_path / "a.py"), "line": 1}}
                },
            }
        )
        assert alert["props"]["redactedValue"] == "*" * len("SuperSecret123!")


class _StubConfig:
    """The slice of Config the alert builders touch."""

    def __init__(self, workspace):
        self.workspace = workspace
        self.output_dir = workspace
        self._config = {}

    def get(self, key, default=None):
        return self._config.get(key, default)

    def get_action_for_severity(self, severity):
        return {"critical": "error", "high": "warn", "medium": "warn", "low": "ignore"}[severity]
