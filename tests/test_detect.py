from honeypot.detect import detect_protocol
from honeypot.models import Protocol


def test_detect_socks5():
    assert detect_protocol(bytes([0x05, 0x01, 0x02])) == Protocol.SOCKS5


def test_detect_http_connect():
    assert detect_protocol(b"CONNECT example.com:443 HTTP/1.1\r\n") == Protocol.HTTP_PROXY


def test_detect_http_get():
    assert detect_protocol(b"GET http://a/ HTTP/1.1\r\n") == Protocol.HTTP_PROXY


def test_detect_unknown():
    assert detect_protocol(b"\x00\x01\x02") == Protocol.UNKNOWN
