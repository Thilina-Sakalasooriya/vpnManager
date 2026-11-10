"""Server inventory: loading, validation and lookup.

The inventory is a plain JSON file listing VPN profiles that already exist
on disk. This tool does not download or scrape server lists -- you point it
at configs you obtained yourself (your own VPS, a provider's account page,
etc.).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

PROTOCOLS = ("openvpn", "wireguard")


class ConfigError(Exception):
    """Raised when the server inventory is missing or malformed."""


def default_config_path() -> Path:
    override = os.environ.get("VPNMANAGER_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "vpnmanager" / "servers.json"


@dataclass
class Server:
    name: str
    protocol: str
    config: str
    country: str = ""
    city: str = ""
    tags: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        place = "/".join(part for part in (self.country, self.city) if part)
        return f"{self.name} ({place})" if place else self.name

    def to_dict(self) -> dict:
        return asdict(self)


def _require_str(raw: dict, key: str, index: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"server #{index}: missing or empty '{key}'")
    return value.strip()


def _parse_server(raw: dict, index: int, base_dir: Path) -> Server:
    if not isinstance(raw, dict):
        raise ConfigError(f"server #{index}: expected an object, got {type(raw).__name__}")

    protocol = _require_str(raw, "protocol", index).lower()
    if protocol not in PROTOCOLS:
        raise ConfigError(
            f"server #{index}: unsupported protocol {protocol!r} "
            f"(expected one of: {', '.join(PROTOCOLS)})"
        )

    config = Path(_require_str(raw, "config", index)).expanduser()
    if not config.is_absolute():
        # Relative paths are resolved against the inventory file's directory,
        # which keeps an inventory portable alongside its configs.
        config = (base_dir / config).resolve()

    if not config.exists():
        raise ConfigError(f"server #{index}: config file not found: {config}")

    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise ConfigError(f"server #{index}: 'tags' must be a list of strings")

    extra = raw.get("extra", {})
    if not isinstance(extra, dict):
        raise ConfigError(f"server #{index}: 'extra' must be an object")

    return Server(
        name=_require_str(raw, "name", index),
        protocol=protocol,
        config=str(config),
        country=str(raw.get("country", "")).strip(),
        city=str(raw.get("city", "")).strip(),
        tags=list(tags),
        extra=dict(extra),
    )


def load_servers(path: Path | str | None = None) -> list[Server]:
    path = Path(path).expanduser() if path else default_config_path()
    if not path.exists():
        raise ConfigError(
            f"no server inventory at {path}\n"
            f"copy servers.example.json there and edit it, or pass --config"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc})") from exc

    entries = payload.get("servers") if isinstance(payload, dict) else payload
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{path}: expected a non-empty 'servers' list")

    servers = [_parse_server(raw, i, path.parent) for i, raw in enumerate(entries)]

    names = [s.name for s in servers]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ConfigError(f"{path}: duplicate server names: {', '.join(sorted(duplicates))}")
    return servers


def find_server(servers: list[Server], ref: str) -> Server:
    """Look a server up by name, or by 1-based index as shown by `list`."""
    for server in servers:
        if server.name == ref:
            return server
    if ref.isdigit():
        index = int(ref) - 1
        if 0 <= index < len(servers):
            return servers[index]
    known = ", ".join(s.name for s in servers)
    raise ConfigError(f"unknown server {ref!r}; known servers: {known}")
