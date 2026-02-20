"""
Socket Basics - Security scanning module

A comprehensive security scanning module that integrates multiple security tools:
- OpenGrep for SAST (Static Application Security Testing)
- Trufflehog for secret scanning
- Trivy for container and Dockerfile scanning

The module includes bundled rules and can be used as a standalone tool or library.
"""

from .socket_basics import SecurityScanner, main
from .core.config import load_config_from_env, Config

__version__ = "1.1.0"
__author__ = "Socket.dev"
__email__ = "support@socket.dev"

__all__ = ["SecurityScanner", "load_config_from_env", "main", "Config"]

# For CLI entry point compatibility
def main_cli():
    """CLI entry point wrapper"""
    return main()
