from honeypot.proto.http_proxy import parse_basic_proxy_auth
import base64


def test_parse_basic():
    token = base64.b64encode(b"admin:secret").decode()
    u, p, scheme = parse_basic_proxy_auth(f"Basic {token}")
    assert scheme == "basic"
    assert u == "admin"
    assert p == "secret"


def test_parse_non_basic():
    u, p, scheme = parse_basic_proxy_auth("Digest abc")
    assert scheme == "digest"
    assert u is None
