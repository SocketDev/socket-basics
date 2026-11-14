"""
Socket Basics - Security scanning module

A comprehensive security scanning module that integrates multiple security tools:
- OpenGrep for SAST (Static Application Security Testing)
- Trufflehog for secret scanning
- Trivy-backed container and Dockerfile scanning support

The module includes bundled rules and can be used as a standalone tool or library.
"""

from .core.config import Config, load_config_from_env
from .socket_basics import SecurityScanner, main

__version__ = "3.4.1"
__author__ = "Socket.dev"
__email__ = "support@socket.dev"

__all__ = ["Config", "SecurityScanner", "load_config_from_env", "main"]


# For CLI entry point compatibility
def main_cli():
    """CLI entry point wrapper"""
    return main()
