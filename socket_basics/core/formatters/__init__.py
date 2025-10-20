"""
Shared formatting library for Socket Security Basics.

This module provides consistent formatting interfaces for converting security findings
into pre-formatted content for different notifier types. All formatters convert
raw findings data into text-based representations suitable for their target platforms.
"""

from .console import ConsoleFormatter
from .markdown import MarkdownFormatter
from .json import JsonFormatter
from .slack import SlackFormatter
from .teams import TeamsFormatter
from .jira import JiraFormatter
from .sentinel import SentinelFormatter
from .sumologic import SumologicFormatter
from .webhook import WebhookFormatter

# Convenience function to get all formatters
def get_all_formatters():
    """Get instances of all available formatters.
    
    Returns:
        Dictionary mapping formatter names to instances
    """
    return {
        'console': ConsoleFormatter(),
        'markdown': MarkdownFormatter(),
        'json': JsonFormatter(),
        'slack': SlackFormatter(),
        'teams': TeamsFormatter(),
        'jira': JiraFormatter(),
        'sentinel': SentinelFormatter(),
        'sumologic': SumologicFormatter(),
        'webhook': WebhookFormatter()
    }

# Export commonly used classes
__all__ = [
    'ConsoleFormatter',
    'MarkdownFormatter', 
    'JsonFormatter',
    'SlackFormatter',
    'TeamsFormatter',
    'JiraFormatter',
    'SentinelFormatter',
    'SumologicFormatter',
    'WebhookFormatter',
    'get_all_formatters'
]