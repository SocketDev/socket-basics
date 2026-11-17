# Connector module for security scanners
from .base import BaseConnector, ConnectorConfigError, ConnectorError, ConnectorExecutionError
from .manager import ConnectorManager

__all__ = [
    "BaseConnector",
    "ConnectorConfigError",
    "ConnectorError",
    "ConnectorExecutionError",
    "ConnectorManager",
]
