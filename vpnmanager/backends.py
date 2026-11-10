"""Protocol backends: how a profile actually gets brought up and torn down.

Every privileged action goes through `Runner`, which means the whole layer is
testable without touching the network and every command is visible with
`--dry-run`.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .config import Server

STATE_DIR = Path(os.environ.get("VPNMANAGER_STATE", Path.home() / ".local" / "state" / "vpnmanager"))


class VPNError(RuntimeError):
    """A VPN action failed."""


def ensure_privileges(dry_run: bool = False) -> None:
    """Fail early with a useful message instead of letting sudo hang."""
    if dry_run or os.geteuid() == 0:
        return
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
    if probe.returncode != 0:
        raise VPNError(
            "this action needs root. Run it as root, or authorise sudo first "
            "with `sudo -v` (a NOPASSWD rule also works)."
        )


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout + self.stderr).strip()


@dataclass
class Status:
    connected: bool
    backend: str
    server: str | None = None
    interface: str | None = None
    details: dict = field(default_factory=dict)


class Runner:
    """Runs commands, adding sudo only when it is actually needed."""

    def __init__(self, dry_run: bool = False, use_sudo: bool = True):
        self.dry_run = dry_run
        self.use_sudo = use_sudo

    def _wrap(self, argv: list[str]) -> list[str]:
        if self.use_sudo and os.geteuid() != 0 and argv[0] not in ("sudo",):
            return ["sudo", "-n", *argv]
        return list(argv)

    def run(self, argv: list[str], timeout: float = 60, check: bool = False) -> CommandResult:
        argv = self._wrap(argv)
        if self.dry_run:
            return CommandResult(0, "dry-run: " + " ".join(shlex.quote(a) for a in argv))
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise VPNError(f"command not found: {argv[0]} (is it installed?)") from exc
        except subprocess.TimeoutExpired as exc:
            raise VPNError(f"timed out after {timeout}s: {' '.join(argv)}") from exc

        result = CommandResult(proc.returncode, proc.stdout, proc.stderr)
        if check and not result.ok:
            raise VPNError(f"command failed ({argv[0]}): {result.output or 'no output'}")
        return result


class Backend(ABC):
    name: str

    def __init__(self, runner: Runner):
        self.runner = runner

    @abstractmethod
    def connect(self, server: Server) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def status(self) -> Status: ...

    def is_available(self) -> bool:
        return True


class OpenVPNBackend(Backend):
    name = "openvpn"

    def __init__(self, runner: Runner):
        super().__init__(runner)
        self.pidfile = STATE_DIR / "openvpn.pid"
        self.logfile = STATE_DIR / "openvpn.log"

    def is_available(self) -> bool:
        return shutil_which("openvpn") is not None

    def _interface_hint(self, config: Path) -> str:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("dev ") and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1]
        return "tun0"

    def connect(self, server: Server) -> None:
        ensure_privileges(self.runner.dry_run)
        if self.status().connected:
            self.disconnect()

        STATE_DIR.mkdir(parents=True, exist_ok=True)
        config = Path(server.config)
        argv = [
            "openvpn",
            "--config", str(config),
            "--daemon", "vpnmanager",
            "--writepid", str(self.pidfile),
            "--log", str(self.logfile),
            "--connect-retry-max", "3",
            "--auth-nocache",
        ]

        extra = server.extra or {}
        if extra.get("auth_file"):
            argv += ["--auth-user-pass", str(Path(extra["auth_file"]).expanduser())]
        if extra.get("no_default_route"):
            # Route only what the profile pushes (split tunnel), instead of
            # taking over the default gateway.
            argv += ["--pull-filter", "ignore", "redirect-gateway"]

        self.runner.run(argv, timeout=90, check=True)
        self._wait_for_pid()

    def _wait_for_pid(self, timeout: float = 30) -> None:
        if self.runner.dry_run:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid = self._read_pid()
            if pid and _pid_alive(pid):
                return
            time.sleep(0.25)
        raise VPNError(f"openvpn did not start; see {self.logfile}")

    def _read_pid(self) -> int | None:
        try:
            return int(self.pidfile.read_text().strip())
        except (OSError, ValueError):
            return None

    def disconnect(self) -> None:
        pid = self._read_pid()
        if pid and _pid_alive(pid):
            ensure_privileges(self.runner.dry_run)
            self.runner.run(["kill", "-TERM", str(pid)])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and _pid_alive(pid):
                time.sleep(0.2)
        self.runner.run(["rm", "-f", str(self.pidfile)])
        self.pidfile.unlink(missing_ok=True)

    def status(self) -> Status:
        pid = self._read_pid()
        if not (pid and _pid_alive(pid)):
            return Status(connected=False, backend=self.name)
        interface = None
        if not self.runner.dry_run:
            probe = self.runner.run(["ip", "-o", "link", "show"], timeout=10)
            for line in probe.stdout.splitlines():
                token = line.split(":", 2)[1].strip() if line.count(":") >= 2 else ""
                if token.startswith(("tun", "tap")):
                    interface = token
                    break
        return Status(
            connected=True,
            backend=self.name,
            server=None,
            interface=interface,
            details={"pid": pid, "log": str(self.logfile)},
        )


class WireGuardBackend(Backend):
    name = "wireguard"

    def is_available(self) -> bool:
        return shutil_which("wg-quick") is not None and shutil_which("wg") is not None

    def _interface(self, server: Server) -> str:
        return server.extra.get("interface") or Path(server.config).stem

    def connect(self, server: Server) -> None:
        ensure_privileges(self.runner.dry_run)
        if self.status().connected:
            self.disconnect()
        self.runner.run(["wg-quick", "up", server.config], timeout=60, check=True)

    def disconnect(self) -> None:
        iface = self._active_interface()
        if not iface:
            return
        ensure_privileges(self.runner.dry_run)
        self.runner.run(["wg-quick", "down", iface], timeout=60, check=True)

    def _active_interface(self) -> str | None:
        if self.runner.dry_run:
            return None
        result = self.runner.run(["wg", "show", "interfaces"], timeout=10)
        interfaces = result.stdout.split()
        return interfaces[0] if interfaces else None

    def status(self) -> Status:
        iface = self._active_interface()
        if not iface:
            return Status(connected=False, backend=self.name)
        return Status(connected=True, backend=self.name, interface=iface)


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def build_backends(runner: Runner) -> dict[str, Backend]:
    return {
        "openvpn": OpenVPNBackend(runner),
        "wireguard": WireGuardBackend(runner),
    }
