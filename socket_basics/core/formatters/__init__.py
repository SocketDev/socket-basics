"""
Shared formatting library for Socket Security Basics.

This module provides consistent formatting interfaces for converting security findings
into pre-formatted content for different notifier types. All formatters convert
raw findings data into text-based representations suitable for their target platforms.
"""

from .console import ConsoleFormatter
from .jira import JiraFormatter
from .json import JsonFormatter
from .markdown import MarkdownFormatter
from .sentinel import SentinelFormatter
from .slack import SlackFormatter
from .sumologic import SumologicFormatter
from .teams import TeamsFormatter
from .webhook import WebhookFormatter


# Convenience function to get all formatters
def get_all_formatters():
    """Get instances of all available formatters.

    Returns:
        Dictionary mapping formatter names to instances
    """
    return {
        "console": ConsoleFormatter(),
        "markdown": MarkdownFormatter(),
        "json": JsonFormatter(),
        "slack": SlackFormatter(),
        "teams": TeamsFormatter(),
        "jira": JiraFormatter(),
        "sentinel": SentinelFormatter(),
        "sumologic": SumologicFormatter(),
        "webhook": WebhookFormatter(),
    }


# Export commonly used classes
__all__ = [
    "ConsoleFormatter",
    "JiraFormatter",
    "JsonFormatter",
    "MarkdownFormatter",
    "SentinelFormatter",
    "SlackFormatter",
    "SumologicFormatter",
    "TeamsFormatter",
    "WebhookFormatter",
    "get_all_formatters",
]
