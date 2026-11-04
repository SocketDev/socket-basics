import pytest

from socket_basics.core.connector.base import ConnectorExecutionError
from socket_basics.core.connector.socket_tier1.scanner import SocketTier1Scanner


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        (
            "--exclude-paths=tests --exclude-paths=fixtures",
            ["--exclude-paths=tests", "--exclude-paths=fixtures"],
        ),
        (
            "--exclude-paths tests --exclude-paths fixtures",
            ["--exclude-paths", "tests", "--exclude-paths", "fixtures"],
        ),
        (
            "--exclude-paths='test data'",
            ["--exclude-paths=test data"],
        ),
        (
            '--exclude-paths="tests,fixtures"',
            ["--exclude-paths=tests,fixtures"],
        ),
        ("--exclude-paths=**/tests", ["--exclude-paths=**/tests"]),
        ("--view=full,--all", ["--view=full", "--all"]),
        (
            "--exclude-paths=tests,fixtures --view=full, --all "
            '--exclude-paths "test data, -literal"',
            [
                "--exclude-paths=tests,fixtures",
                "--view=full",
                "--all",
                "--exclude-paths",
                "test data, -literal",
            ],
        ),
        (
            '--note="quoted, --option text"',
            ["--note=quoted, --option text"],
        ),
        (r"--note=left\, --option", ["--note=left,", "--option"]),
    ],
)
def test_parse_additional_params_preserves_argument_boundaries(raw, expected):
    scanner = SocketTier1Scanner({"socket_additional_params": raw})

    assert scanner._parse_additional_params() == expected


def test_parse_additional_params_reports_malformed_shell_quotes():
    scanner = SocketTier1Scanner({"socket_additional_params": '--exclude-paths "tests'})

    with pytest.raises(
        ConnectorExecutionError,
        match="Invalid socket_additional_params: No closing quotation",
    ):
        scanner._parse_additional_params()
