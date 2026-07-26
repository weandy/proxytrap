"""Guard: honeypot handlers must never dial or relay upstream."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from honeypot.models import AuthMode
from honeypot.proto import http_proxy, socks5

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "honeypot"

# Names that would indicate outbound proxying if used for client traffic.
FORBIDDEN_CALLS = {
    "open_connection",
    "create_connection",
    "create_server",  # not for outbound; keep list focused on client dials below
}

FORBIDDEN_ATTRS = {
    "create_connection",
    "open_connection",
}


def _collect_calls(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


@pytest.mark.parametrize(
    "rel",
    [
        "proto/socks5.py",
        "proto/http_proxy.py",
        "server.py",
    ],
)
def test_handlers_have_no_outbound_dial_api(rel: str):
    path = SRC_ROOT / rel
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    calls = _collect_calls(tree)
    # asyncio.open_connection / socket.create_connection must not appear
    bad = calls & {"open_connection", "create_connection"}
    assert not bad, f"{rel} uses outbound dial APIs: {bad}"


def test_modules_document_no_forward():
    assert "never forward" in socks5.handle_socks5.__doc__.lower()
    assert "never forward" in http_proxy.handle_http_proxy.__doc__.lower()


def test_auth_modes_do_not_include_forward():
    values = {m.value for m in AuthMode}
    assert "always_fail" in values
    assert "accept_then_fail" in values
    assert "forward" not in values
    assert "open_proxy" not in values
