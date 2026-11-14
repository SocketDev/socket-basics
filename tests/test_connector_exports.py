from socket_basics.core.connector.socket_tier1 import SocketTier1Scanner
from socket_basics.core.connector.socket_tier1.scanner import (
    SocketTier1Scanner as ScannerImplementation,
)
from socket_basics.core.connector.trivy import TrivyScanner
from socket_basics.core.connector.trivy.trivy import TrivyScanner as TrivyImplementation


def test_connector_package_exports_remain_available():
    assert SocketTier1Scanner is ScannerImplementation
    assert TrivyScanner is TrivyImplementation
