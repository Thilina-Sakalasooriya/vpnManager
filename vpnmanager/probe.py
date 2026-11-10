"""What is this connection actually good for?

Three signals, cheapest first:

1. public IP            -- did traffic leave through the tunnel at all?
2. ASN / organisation   -- is this a datacenter range? Streaming services
                           blacklist those wholesale.
3. Netflix reachability -- fetch a title page and see how Netflix answers.

Signal 3 is a heuristic, not a guarantee: a definitive "yes" requires a
signed-in session, and Netflix varies answers by device and account. Treat
"blocked" as reliable and "plausible" as merely "worth trying".
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

NETFLIX_TITLE_URL = "https://www.netflix.com/title/80018499"
IPIFY_URL = "https://api.ipify.org?format=json"
IPINFO_URL = "https://ipinfo.io/{ip}/json"

# Cloud/CDN/hosting strings seen in ASN organisation names. Matching any of
# these means the exit IP is a datacenter address, i.e. almost certainly
# blocked by streaming services.
HOSTING_MARKERS = (
    "hosting", "cloud", "server", "datacenter", "data center", "colocation",
    "vps", "dedicated", "digitalocean", "linode", "vultr", "ovh", "hetzner",
    "amazon", "aws", "google", "microsoft", "azure", "oracle", "contabo",
    "leaseweb", "m247", "choopa", "psychz", "hostwinds", "racknerd", "cherry",
    "serverius", "datacamp", "gcore", "scaleway", "upcloud", "kamatera",
)

BLOCK_MARKERS = (
    "not available in your country",
    "unavailable in your country",
    "you seem to be using a vpn",
    "you seem to be using an unblocker",
    "your device is not part of the netflix household",
    "whoops, something went wrong",
)


@dataclass
class HttpResult:
    status: int
    final_url: str
    body: str = ""
    error: str | None = None


@dataclass
class Geo:
    ip: str = ""
    country: str = ""
    city: str = ""
    org: str = ""
    hosting: bool | None = None
    error: str | None = None


@dataclass
class NetflixResult:
    verdict: str            # "blocked" | "plausible" | "unknown"
    reason: str
    http_status: int | None = None
    final_url: str = ""


@dataclass
class Report:
    ip: str = ""
    country: str = ""
    city: str = ""
    org: str = ""
    hosting: bool | None = None
    latency_ms: float | None = None
    netflix: NetflixResult = field(default_factory=lambda: NetflixResult("unknown", "not checked"))
    error: str | None = None

    @property
    def streamable(self) -> bool:
        return self.netflix.verdict == "plausible" and self.hosting is False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http_get(url: str, timeout: float = 12.0, headers: dict | None = None) -> HttpResult:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8", **(headers or {})},
    )
    try:
        with _opener.open(request, timeout=timeout) as response:
            body = response.read(400_000).decode("utf-8", "replace")
            return HttpResult(response.status, response.geturl(), body)
    except urllib.error.HTTPError as exc:
        # Redirects surface here because the redirect handler is disabled.
        body = ""
        try:
            body = exc.read(400_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - body is best-effort
            pass
        location = exc.headers.get("Location", "") if exc.headers else ""
        return HttpResult(exc.code, location or url, body)
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        return HttpResult(0, url, "", error=str(getattr(exc, "reason", exc)))


class Prober:
    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    def public_ip(self) -> str:
        result = http_get(IPIFY_URL, self.timeout)
        if result.error or result.status != 200:
            raise RuntimeError(f"could not determine public IP: {result.error or result.status}")
        return json.loads(result.body)["ip"]

    def geo(self, ip: str) -> Geo:
        result = http_get(IPINFO_URL.format(ip=ip), self.timeout)
        if result.error or result.status != 200:
            return Geo(ip=ip, error=result.error or f"HTTP {result.status}")
        try:
            data = json.loads(result.body)
        except json.JSONDecodeError:
            return Geo(ip=ip, error="invalid JSON from ipinfo.io")
        org = str(data.get("org", ""))
        return Geo(
            ip=ip,
            country=str(data.get("country", "")),
            city=str(data.get("city", "")),
            org=org,
            hosting=_looks_like_hosting(org),
        )

    def netflix(self) -> NetflixResult:
        result = http_get(NETFLIX_TITLE_URL, self.timeout)
        if result.error:
            return NetflixResult("unknown", f"request failed: {result.error}")

        if 300 <= result.status < 400:
            target = result.final_url.lower()
            if "/title/" in target:
                return NetflixResult(
                    "blocked", "redirected to a title page (region lock)", result.status, result.final_url
                )
            if "login" in target:
                return NetflixResult("unknown", "redirected to login", result.status, result.final_url)
            return NetflixResult("blocked", "redirected away from title", result.status, result.final_url)

        if result.status == 200:
            lowered = result.body.lower()
            for marker in BLOCK_MARKERS:
                if marker in lowered:
                    return NetflixResult("blocked", f"page says: {marker!r}", 200, result.final_url)
            if "netflix" in lowered:
                return NetflixResult(
                    "plausible",
                    "title page served without a proxy/locale error",
                    200,
                    result.final_url,
                )
            return NetflixResult("unknown", "unrecognised page body", 200, result.final_url)

        if result.status == 403:
            return NetflixResult("blocked", "HTTP 403 (proxy/VPN detected)", 403, result.final_url)
        if result.status == 404:
            return NetflixResult("blocked", "HTTP 404 (title not in this region)", 404, result.final_url)
        return NetflixResult("unknown", f"HTTP {result.status}", result.status, result.final_url)

    def check(self) -> Report:
        started = time.perf_counter()
        try:
            ip = self.public_ip()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return Report(error=str(exc))
        latency = (time.perf_counter() - started) * 1000

        geo = self.geo(ip)
        report = Report(
            ip=ip,
            country=geo.country,
            city=geo.city,
            org=geo.org,
            hosting=geo.hosting,
            latency_ms=round(latency, 1),
        )
        if geo.error:
            report.error = f"geo lookup failed: {geo.error}"
        report.netflix = self.netflix()
        return report


def _looks_like_hosting(org: str) -> bool | None:
    if not org:
        return None
    lowered = org.lower()
    return any(marker in lowered for marker in HOSTING_MARKERS)
