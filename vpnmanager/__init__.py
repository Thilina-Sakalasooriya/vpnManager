"""VPN Manager package."""

__version__ = "0.1.0"

from .config import ConfigError, Server, find_server, load_servers
from .manager import VPNManager, TestResult

__all__ = ["ConfigError", "Server", "VPNManager", "TestResult", "find_server", "load_servers"]
