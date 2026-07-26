from __future__ import annotations

from honeypot.models import Protocol

_HTTP_METHODS = (
    b"CONNECT",
    b"GET",
    b"HEAD",
    b"POST",
    b"PUT",
    b"OPTIONS",
    b"DELETE",
    b"PATCH",
    b"TRACE",
)


def detect_protocol(first_bytes: bytes) -> Protocol:
    """Detect SOCKS5 or HTTP proxy from first bytes of a connection."""
    if not first_bytes:
        return Protocol.UNKNOWN
    # SOCKS5 greeting: VER=0x05
    if first_bytes[0] == 0x05:
        return Protocol.SOCKS5
    # TLS ClientHello — reserved for future TLS-wrapped proxy ports
    if len(first_bytes) >= 2 and first_bytes[0] == 0x16 and first_bytes[1] == 0x03:
        return Protocol.UNKNOWN
    upper = first_bytes[:16].upper()
    for method in _HTTP_METHODS:
        if upper.startswith(method) and (
            len(first_bytes) == len(method) or first_bytes[len(method) : len(method) + 1] in (b" ", b"\t")
        ):
            return Protocol.HTTP_PROXY
        if upper.startswith(method + b" "):
            return Protocol.HTTP_PROXY
    # Some clients send lowercase
    lower = first_bytes[:16].lower()
    for method in _HTTP_METHODS:
        m = method.lower()
        if lower.startswith(m + b" "):
            return Protocol.HTTP_PROXY
    return Protocol.UNKNOWN


def first_bytes_hex(data: bytes, limit: int = 32) -> str:
    return data[:limit].hex()
