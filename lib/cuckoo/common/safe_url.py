"""URL safety helpers for outbound HTTP fetches.

The malware-sandbox dlnexec/3rd-party download paths take URLs from
remote API clients and pass them to `requests.get()`.  Without
validation, an attacker can pivot through the sandbox host to reach
internal services (RFC1918, loopback, link-local cloud metadata at
169.254.169.254, carrier-grade NAT at 100.64/10).

`SafeURLError` is raised for any URL that resolves to a non-global
address or uses a non-HTTP scheme.  Callers should catch it and surface
a generic "URL rejected" error to the user — never the underlying
message, to avoid disclosing internal network shape.

Limitations:
- This validates at the DNS level once, then calls `requests.get`.
  Between those two operations the attacker controlling the DNS can
  rebind the name to an internal IP (TOCTOU).  Pin the IP and use a
  custom `requests` Transport adapter for full mitigation.
- Only checks scheme/host; does not inspect the response body.
"""

import ipaddress
import logging
import socket
from typing import Iterable, Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

_DEFAULT_SCHEMES: tuple = ("http", "https")
_DEFAULT_TIMEOUT_S = 30
_DEFAULT_MAX_REDIRECTS = 5


class SafeURLError(ValueError):
    """Raised when a URL is rejected as unsafe to fetch."""


def _resolved_addrs(host: str) -> Iterable[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SafeURLError(f"could not resolve host: {e}") from e
    for _family, _type, _proto, _canon, sockaddr in infos:
        yield sockaddr[0]


def validate_url(url: str, allowed_schemes: Iterable[str] = _DEFAULT_SCHEMES) -> str:
    """Reject URLs that point to internal/private/reserved addresses.

    Returns the URL on success; raises SafeURLError on failure.
    """
    parsed = urlparse(url)
    if parsed.scheme not in allowed_schemes:
        raise SafeURLError(f"scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise SafeURLError("URL has no host component")

    for addr in _resolved_addrs(host):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise SafeURLError(f"unparseable resolved address: {addr!r}")
        # `is_global` is True only for public-Internet addresses.  This
        # excludes loopback (127/8, ::1), link-local (169.254/16, fe80::/10
        # — covers AWS/GCP/Azure/DO metadata at 169.254.169.254), private
        # (RFC1918, fc00::/7), carrier-grade NAT (100.64/10 — covers
        # Alibaba metadata at 100.100.100.200), multicast, reserved, etc.
        if not ip.is_global:
            raise SafeURLError(f"host resolves to non-global address: {ip}")
    return url


def safe_get(
    url: str,
    *,
    allowed_schemes: Iterable[str] = _DEFAULT_SCHEMES,
    timeout: float = _DEFAULT_TIMEOUT_S,
    max_redirects: int = _DEFAULT_MAX_REDIRECTS,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    proxies: Optional[dict] = None,
    verify: bool = True,
) -> requests.Response:
    """Validate `url`, then issue a GET.

    Re-validates the URL on every redirect hop so an attacker-controlled
    302 to `http://169.254.169.254/` is blocked.
    """
    validate_url(url, allowed_schemes)

    session = requests.Session()
    session.max_redirects = max_redirects
    # We follow redirects manually so we can re-validate each hop.
    current = url
    for _ in range(max_redirects + 1):
        resp = session.get(
            current,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=verify,
            timeout=timeout,
            allow_redirects=False,
        )
        if resp.status_code in (301, 302, 303, 307, 308):
            target = resp.headers.get("Location")
            if not target:
                return resp
            # Re-validate; raises SafeURLError on a bad hop.
            validate_url(target, allowed_schemes)
            current = target
            continue
        return resp
    raise SafeURLError(f"too many redirects ({max_redirects})")
