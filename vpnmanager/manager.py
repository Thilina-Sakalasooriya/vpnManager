"""Orchestration: connect, tear down, and decide which server is worth using."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config as config_module
from .backends import STATE_DIR, Backend, Runner, Status, VPNError, build_backends
from .config import Server
from .probe import Prober, Report


@dataclass
class TestResult:
    server: str
    protocol: str
    country: str = ""
    ip: str = ""
    org: str = ""
    hosting: bool | None = None
    latency_ms: float | None = None
    netflix: str = "unknown"
    netflix_reason: str = ""
    error: str | None = None

    @property
    def streamable(self) -> bool:
        return self.netflix == "plausible" and self.hosting is False

    def to_dict(self) -> dict:
        return asdict(self)


class VPNManager:
    def __init__(
        self,
        config_path: Path | str | None = None,
        runner: Runner | None = None,
        prober: Prober | None = None,
        settle_seconds: float = 2.0,
    ):
        self.config_path = Path(config_path).expanduser() if config_path else config_module.default_config_path()
        self.runner = runner or Runner()
        self.prober = prober or Prober()
        self.backends: dict[str, Backend] = build_backends(self.runner)
        self.settle_seconds = settle_seconds
        self._servers: list[Server] | None = None

    # -- inventory -----------------------------------------------------

    @property
    def servers(self) -> list[Server]:
        if self._servers is None:
            self._servers = config_module.load_servers(self.config_path)
        return self._servers

    def resolve(self, ref: str) -> Server:
        return config_module.find_server(self.servers, ref)

    def backend_for(self, server: Server) -> Backend:
        backend = self.backends[server.protocol]
        if not backend.is_available():
            raise VPNError(
                f"{server.protocol} is not installed; install the "
                f"{'openvpn' if server.protocol == 'openvpn' else 'wireguard-tools'} package"
            )
        return backend

    # -- connection lifecycle ------------------------------------------

    def status(self) -> Status:
        for backend in self.backends.values():
            status = backend.status()
            if status.connected:
                return status
        return Status(connected=False, backend="none")

    def connect(self, ref: str) -> Server:
        server = self.resolve(ref)
        backend = self.backend_for(server)
        connected = self.status()
        if connected.connected:
            if connected.backend == server.protocol:
                self.disconnect()
            else:
                raise VPNError(
                    f"{connected.backend} is already connected; disconnect it first "
                    f"(one tunnel at a time keeps routing predictable)"
                )
        backend.connect(server)
        self._remember_active(server)
        return server

    def disconnect(self) -> bool:
        status = self.status()
        if not status.connected:
            return False
        self.backends[status.backend].disconnect()
        self._remember_active(None)
        return True

    def _remember_active(self, server: Server | None) -> None:
        path = STATE_DIR / "active.json"
        if self.runner.dry_run:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        if server is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(json.dumps({"server": server.name, "protocol": server.protocol}))

    def active_server_name(self) -> str | None:
        try:
            return json.loads((STATE_DIR / "active.json").read_text()).get("server")
        except (OSError, json.JSONDecodeError):
            return None

    # -- evaluation ----------------------------------------------------

    def check_current(self) -> Report:
        return self.prober.check()

    def test(self, refs: list[str] | None = None) -> list[TestResult]:
        """Connect to each server in turn, measure it, and tear it down.

        This is the only reliable way to know whether a given exit IP is
        usable: reputation is per-IP and changes over time.
        """
        targets = [self.resolve(ref) for ref in refs] if refs else list(self.servers)
        results: list[TestResult] = []
        for server in targets:
            results.append(self._test_one(server))
        self._save_results(results)
        return results

    def _test_one(self, server: Server) -> TestResult:
        result = TestResult(server=server.name, protocol=server.protocol, country=server.country)
        try:
            self.connect(server.name)
            if self.settle_seconds:
                time.sleep(self.settle_seconds)
            report = self.check_current()
            result.ip = report.ip
            result.org = report.org
            result.hosting = report.hosting
            result.latency_ms = report.latency_ms
            result.netflix = report.netflix.verdict
            result.netflix_reason = report.netflix.reason
            result.error = report.error
        except (VPNError, RuntimeError) as exc:
            result.error = str(exc)
        finally:
            try:
                self.disconnect()
            except VPNError as exc:
                result.error = f"{result.error or ''} (cleanup failed: {exc})".strip()
        return result

    def best(self, refs: list[str] | None = None) -> TestResult | None:
        """Reuse cached results when they exist, otherwise measure now."""
        candidates = self._load_results()
        if refs:
            wanted = {self.resolve(ref).name for ref in refs}
            candidates = [c for c in candidates if c.server in wanted]
        if not candidates:
            candidates = self.test(refs)
        ranked = sorted(
            (c for c in candidates if c.streamable),
            key=lambda c: c.latency_ms if c.latency_ms is not None else float("inf"),
        )
        return ranked[0] if ranked else None

    def connect_best(self, refs: list[str] | None = None) -> TestResult:
        winner = self.best(refs)
        if winner is None:
            raise VPNError(
                "no server passed: every candidate was either detected as a hosting "
                "IP or blocked by Netflix. Free public servers almost always fail here."
            )
        self.connect(winner.server)
        return winner

    # -- result cache --------------------------------------------------

    @property
    def results_path(self) -> Path:
        return STATE_DIR / "results.json"

    def _save_results(self, results: list[TestResult]) -> None:
        if self.runner.dry_run:
            return
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "results": [r.to_dict() for r in results],
        }
        self.results_path.write_text(json.dumps(payload, indent=2))

    def _load_results(self) -> list[TestResult]:
        try:
            payload = json.loads(self.results_path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        out: list[TestResult] = []
        for item in payload.get("results", []):
            try:
                out.append(TestResult(**item))
            except TypeError:
                continue
        return out
