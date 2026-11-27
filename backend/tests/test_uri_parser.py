"""Unit tests for app.uri_parser (all 6 protocols + edge cases).

All fixtures use fake hosts (example.com), fake UUIDs and fake
passwords — no real credentials anywhere.
"""

import base64
import json

import pytest

from app.uri_parser import parse_uri

UUID = "11111111-2222-3333-4444-555555555555"


def _b64(text: str, urlsafe: bool = False) -> str:
    raw = text.encode("utf-8")
    if urlsafe:
        return base64.urlsafe_b64encode(raw).decode()
    return base64.b64encode(raw).decode()


# ------------------------------------------------------------------ vless
def test_vless_tls_ws():
    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?encryption=none&security=tls"
        "&sni=example.com&alpn=h2,http/1.1&fp=chrome&type=ws"
        "&path=%2Fws&host=example.com#Test-VLESS-WS"
    )
    assert proxy == {
        "name": "Test-VLESS-WS",
        "type": "vless",
        "server": "example.com",
        "port": 443,
        "uuid": UUID,
        "network": "ws",
        "ws-opts": {"path": "/ws", "headers": {"Host": "example.com"}},
        "tls": True,
        "servername": "example.com",
        "alpn": ["h2", "http/1.1"],
        "client-fingerprint": "chrome",
    }


def test_vless_reality():
    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?encryption=none&security=reality"
        "&sni=example.com&fp=chrome&pbk=PUBKEYEXAMPLE&sid=abcd1234"
        "&type=tcp#Test-Reality"
    )
    assert proxy["type"] == "vless"
    assert proxy["tls"] is True
    assert proxy["servername"] == "example.com"
    assert proxy["client-fingerprint"] == "chrome"
    assert proxy["reality-opts"] == {
        "public-key": "PUBKEYEXAMPLE",
        "short-id": "abcd1234",
    }
    assert proxy["network"] == "tcp"


def test_vless_xtls_vision_grpc():
    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?encryption=none&security=tls"
        "&sni=example.com&flow=xtls-rprx-vision&type=tcp#Test-Vision"
    )
    assert proxy["flow"] == "xtls-rprx-vision"
    assert proxy["tls"] is True

    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?encryption=none&security=tls"
        "&sni=example.com&type=grpc&serviceName=grpc-svc#Test-gRPC"
    )
    assert proxy["network"] == "grpc"
    assert proxy["grpc-opts"] == {"grpc-service-name": "grpc-svc"}


def test_vless_plain_no_tls():
    proxy = parse_uri(f"vless://{UUID}@example.com:8086#Plain")
    assert proxy.get("tls") is not True
    assert proxy["network"] == "tcp"
    assert proxy["name"] == "Plain"


def test_vless_default_name():
    proxy = parse_uri(f"vless://{UUID}@example.com:443")
    assert proxy["name"] == "vless-example.com"


# ------------------------------------------------------------------ vmess
def _vmess_uri(payload: dict, strip_padding: bool = False) -> str:
    encoded = _b64(json.dumps(payload, separators=(",", ":")))
    if strip_padding:
        encoded = encoded.rstrip("=")
    return f"vmess://{encoded}"


def test_vmess_standard():
    proxy = parse_uri(_vmess_uri({
        "v": "2", "ps": "Test-VMess", "add": "example.com", "port": 443,
        "id": UUID, "aid": 0, "scy": "auto", "net": "ws",
        "type": "none", "host": "example.com", "path": "/vmess",
        "tls": "tls", "sni": "example.com",
    }))
    assert proxy == {
        "name": "Test-VMess",
        "type": "vmess",
        "server": "example.com",
        "port": 443,
        "uuid": UUID,
        "alterId": 0,
        "cipher": "auto",
        "tls": True,
        "servername": "example.com",
        "network": "ws",
        "ws-opts": {"path": "/vmess", "headers": {"Host": "example.com"}},
    }


def test_vmess_missing_padding():
    payload = {
        "v": "2", "ps": "NoPad", "add": "example.com", "port": 80,
        "id": UUID, "aid": 0, "net": "tcp", "tls": "",
    }
    text = json.dumps(payload, separators=(",", ":"))
    # Base64 only carries '=' padding when len(text) % 3 != 0; pad the
    # JSON with trailing spaces (still valid JSON) so the fixture is
    # guaranteed to test the missing-padding path.
    while len(text) % 3 == 0:
        text += " "
    assert _b64(text).endswith("=")
    proxy = parse_uri(f"vmess://{_b64(text).rstrip('=')}")
    assert proxy["name"] == "NoPad"
    assert proxy["tls"] is False


def test_vmess_grpc_and_defaults():
    proxy = parse_uri(_vmess_uri({
        "ps": "gRPC", "add": "example.com", "port": "8443",
        "id": UUID, "net": "grpc", "path": "vmess-grpc",
    }))
    assert proxy["port"] == 8443
    assert proxy["alterId"] == 0
    assert proxy["cipher"] == "auto"
    assert proxy["grpc-opts"] == {"grpc-service-name": "vmess-grpc"}


# --------------------------------------------------------------------- ss
def test_ss_sip002():
    userinfo = _b64("aes-128-gcm:testpass", urlsafe=True).rstrip("=")
    proxy = parse_uri(f"ss://{userinfo}@example.com:8388#Test-SS")
    assert proxy == {
        "name": "Test-SS",
        "type": "ss",
        "server": "example.com",
        "port": 8388,
        "cipher": "aes-128-gcm",
        "password": "testpass",
    }


def test_ss_legacy_base64():
    encoded = _b64("aes-256-gcm:legacy-pass@example.com:8388")
    proxy = parse_uri(f"ss://{encoded}#Legacy-SS")
    assert proxy["name"] == "Legacy-SS"
    assert proxy["cipher"] == "aes-256-gcm"
    assert proxy["password"] == "legacy-pass"
    assert proxy["server"] == "example.com"
    assert proxy["port"] == 8388


def test_ss_legacy_base64_with_slash():
    # A legacy payload whose Base64 contains '/' breaks naive
    # urlparse().netloc splitting ('/' starts the path). The password
    # 'pa?ss' puts '?' at index 2 (mod 3), which yields '/' in the
    # encoding — it also proves a '?' inside a password is not
    # mistaken for the plugin-query delimiter.
    encoded = _b64("aes-128-gcm:pa?ss@example.com:8388")
    assert "/" in encoded
    proxy = parse_uri(f"ss://{encoded}#Slash-SS")
    assert proxy["password"] == "pa?ss"
    assert proxy["server"] == "example.com"
    assert proxy["port"] == 8388


def test_ss_plugin_obfs():
    userinfo = _b64("chacha20-ietf-poly1305:pluginpass")
    plugin = "obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com"
    proxy = parse_uri(
        f"ss://{userinfo}@example.com:8388?plugin={plugin}#SS-Plugin"
    )
    assert proxy["plugin"] == "obfs-local"
    assert proxy["plugin-opts"] == {"mode": "http", "host": "example.com"}


def test_ss_2022_blake3_cipher():
    userinfo = _b64("2022-blake3-aes-128-gcm:fake2022key")
    proxy = parse_uri(f"ss://{userinfo}@example.com:8388#SS-2022")
    assert proxy["cipher"] == "2022-blake3-aes-128-gcm"


# ----------------------------------------------------------------- trojan
def test_trojan_basic():
    proxy = parse_uri(
        "trojan://trojanpass@example.com:443?sni=example.com"
        "&alpn=h2,http/1.1#Test-Trojan"
    )
    assert proxy == {
        "name": "Test-Trojan",
        "type": "trojan",
        "server": "example.com",
        "port": 443,
        "password": "trojanpass",
        "sni": "example.com",
        "alpn": ["h2", "http/1.1"],
    }


def test_trojan_ws():
    proxy = parse_uri(
        "trojan://trojanpass@example.com:443?sni=example.com&type=ws"
        "&path=%2Ftrojan&host=example.com#Trojan-WS"
    )
    assert proxy["network"] == "ws"
    assert proxy["ws-opts"] == {
        "path": "/trojan", "headers": {"Host": "example.com"},
    }


# -------------------------------------------------------------- hysteria2
def test_hysteria2():
    proxy = parse_uri(
        "hysteria2://hy2pass@example.com:8443?sni=example.com&insecure=1"
        "&obfs=salamander&obfs-password=obfspass&alpn=h3#Test-HY2"
    )
    assert proxy == {
        "name": "Test-HY2",
        "type": "hysteria2",
        "server": "example.com",
        "port": 8443,
        "password": "hy2pass",
        "sni": "example.com",
        "skip-cert-verify": True,
        "obfs": "salamander",
        "obfs-password": "obfspass",
        "alpn": ["h3"],
    }


def test_hy2_alias():
    proxy = parse_uri("hy2://hy2pass@example.com:8443#HY2-Alias")
    assert proxy["type"] == "hysteria2"
    assert proxy["name"] == "HY2-Alias"


# -------------------------------------------------------------------- tuic
def test_tuic():
    proxy = parse_uri(
        f"tuic://{UUID}:tuicpass@example.com:443"
        "?congestion_control=bbr&udp_relay_mode=native"
        "&sni=example.com&alpn=h3#Test-TUIC"
    )
    assert proxy == {
        "name": "Test-TUIC",
        "type": "tuic",
        "server": "example.com",
        "port": 443,
        "uuid": UUID,
        "password": "tuicpass",
        "congestion-controller": "bbr",
        "udp-relay-mode": "native",
        "sni": "example.com",
        "alpn": ["h3"],
    }


# ------------------------------------------------------------------ errors
@pytest.mark.parametrize("bad_uri,match", [
    ("not-a-uri", "missing scheme"),
    ("socks5://user@example.com:1080", "unsupported.*socks5"),
    ("vless://@example.com:443", "missing the UUID"),
    ("vless://" + UUID + "@example.com", "missing a port"),
    ("vless://" + UUID + "@example.com:99999", "invalid port"),
    ("vless://" + UUID + "@example.com:abc", "invalid port"),
    ("vmess://A", "invalid Base64"),
    ("vmess://" + _b64("this is not json"), "not valid JSON"),
    ("ss://", "missing '@'"),
    ("trojan://@example.com:443", "missing the password"),
    ("hysteria2://@example.com:8443", "missing the password"),
    ("tuic://onlyuuid@example.com:443", "uuid:password"),
    ("tuic://:nopass@example.com:443", "missing the UUID or password"),
])
def test_malformed_uris_raise(bad_uri, match):
    with pytest.raises(ValueError, match=match):
        parse_uri(bad_uri)


def test_scheme_case_insensitive():
    proxy = parse_uri(f"VLESS://{UUID}@example.com:443#Upper")
    assert proxy["type"] == "vless"


# ------------------------------------------------- M-15: validation on parse
@pytest.mark.parametrize("bad_uri,match", [
    # Invalid UUIDs are rejected, not stored.
    (f"vless://not-a-uuid@example.com:443", "invalid UUID"),
    ("tuic://not-a-uuid:tuicpass@example.com:443", "invalid UUID"),
    # Invalid hosts are rejected (underscore / illegal chars).
    (f"vless://{UUID}@bad_host!.com:443", "invalid server address"),
    # Unknown ciphers are rejected.
    (
        "ss://" + _b64("bad-cipher:somepass") + "@example.com:8388#BadCipher",
        "unsupported cipher",
    ),
])
def test_parse_rejects_invalid_uuid_host_cipher(bad_uri, match):
    with pytest.raises(ValueError, match=match):
        parse_uri(bad_uri)


def test_parse_rejects_invalid_vmess_uuid_and_cipher():
    with pytest.raises(ValueError, match="invalid UUID"):
        parse_uri(_vmess_uri({
            "ps": "Bad", "add": "example.com", "port": 443,
            "id": "not-a-uuid", "net": "tcp",
        }))
    with pytest.raises(ValueError, match="unsupported cipher"):
        parse_uri(_vmess_uri({
            "ps": "Bad", "add": "example.com", "port": 443,
            "id": UUID, "net": "tcp", "scy": "bad-cipher",
        }))


# ------------------------------------------------- M-16: vmess tls by type
@pytest.mark.parametrize("tls_value,expected", [
    (True, True),          # boolean true enables TLS (was: silently False)
    (False, False),
    ("tls", True),
    ("reality", True),     # string "reality" keeps its original meaning
    ("TLS", True),
    ("", False),
    ("false", False),
    (1, True),
    (0, False),
])
def test_vmess_tls_by_type(tls_value, expected):
    proxy = parse_uri(_vmess_uri({
        "ps": "T", "add": "example.com", "port": 443,
        "id": UUID, "net": "tcp", "tls": tls_value,
    }))
    assert proxy["tls"] is expected


def test_vmess_tls_unknown_value_rejected():
    with pytest.raises(ValueError, match="unknown tls value"):
        parse_uri(_vmess_uri({
            "ps": "T", "add": "example.com", "port": 443,
            "id": UUID, "net": "tcp", "tls": "weird",
        }))


# ------------------------------------------------- M-17: SS non-ASCII password
def test_ss_chinese_password_sip002():
    userinfo = _b64("aes-128-gcm:中文密码", urlsafe=True).rstrip("=")
    proxy = parse_uri(f"ss://{userinfo}@example.com:8388#CN-Pass")
    assert proxy["password"] == "中文密码"
    assert proxy["cipher"] == "aes-128-gcm"


def test_ss_chinese_password_legacy():
    encoded = _b64("aes-256-gcm:密码123@example.com:8388")
    proxy = parse_uri(f"ss://{encoded}#CN-Legacy")
    assert proxy["password"] == "密码123"


# ------------------------------------------------- M-18: SS plugin leading ';'
def test_ss_plugin_leading_semicolon():
    userinfo = _b64("aes-128-gcm:pluginpass")
    proxy = parse_uri(
        "ss://" + userinfo + "@example.com:8388"
        "?plugin=%3Bobfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#P"
    )
    assert proxy["plugin"] == "obfs-local"
    assert proxy["plugin-opts"] == {"mode": "http", "host": "example.com"}


def test_ss_plugin_options_only_after_leading_semicolon():
    # ";obfs=http" has no plugin name at all: the option must not
    # become the plugin name (previously: plugin == "obfs=http").
    userinfo = _b64("aes-128-gcm:pluginpass")
    proxy = parse_uri(
        "ss://" + userinfo + "@example.com:8388"
        "?plugin=%3Bobfs%3Dhttp#P"
    )
    assert "plugin" not in proxy
    assert proxy["plugin-opts"] == {"mode": "http"}


# ------------------------------------------- M-22 / L-10: duplicate params
def test_duplicate_query_param_last_wins_with_warning():
    from app.uri_parser import parse_uri_with_warnings
    proxy, warnings = parse_uri_with_warnings(
        f"vless://{UUID}@example.com:443?security=tls"
        "&sni=first.example&sni=second.example#Dup"
    )
    assert proxy["servername"] == "second.example"
    assert any("duplicate query parameter 'sni'" in w for w in warnings)


def test_unknown_query_param_warned_not_fatal():
    from app.uri_parser import parse_uri_with_warnings
    proxy, warnings = parse_uri_with_warnings(
        f"vless://{UUID}@example.com:443?security=tls"
        "&sni=example.com&bogusparam=1#Unk"
    )
    assert proxy["tls"] is True
    assert any("unknown query parameter 'bogusparam'" in w for w in warnings)


# ------------------------------------------------- L-07: param names lowercase
def test_param_names_case_insensitive():
    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?Security=TLS&SNI=UP.example.com"
        "&Type=ws&Path=%2Fws#Case"
    )
    assert proxy["tls"] is True
    assert proxy["servername"] == "UP.example.com"
    assert proxy["network"] == "ws"

    proxy = parse_uri(
        "trojan://trojanpass@example.com:443?SNI=up.example.com#CaseTrojan"
    )
    assert proxy["sni"] == "up.example.com"


# ------------------------------------------------- L-08: hy2/tuic port range
@pytest.mark.parametrize("bad_uri", [
    "hysteria2://hy2pass@example.com:0#Bad",
    "hysteria2://hy2pass@example.com:99999#Bad",
    f"tuic://{UUID}:tuicpass@example.com:0#Bad",
    f"tuic://{UUID}:tuicpass@example.com:70000#Bad",
])
def test_hy2_tuic_port_range(bad_uri):
    with pytest.raises(ValueError, match="port"):
        parse_uri(bad_uri)


# ------------------------------------------------- L-09: base64 both alphabets
def test_ss_standard_alphabet_base64_with_slash():
    # Standard alphabet ('/' in the payload) decodes identically.
    encoded = _b64("aes-128-gcm:pa?ss@example.com:8388")
    assert "/" in encoded
    proxy = parse_uri(f"ss://{encoded}#StdB64")
    assert proxy["password"] == "pa?ss"


def test_ss_userinfo_urlsafe_and_unpadded():
    userinfo = _b64("aes-128-gcm:urlsafe-pass", urlsafe=True).rstrip("=")
    assert "=" not in userinfo
    proxy = parse_uri(f"ss://{userinfo}@example.com:8388#Urlsafe")
    assert proxy["password"] == "urlsafe-pass"


# ------------------------------------------------- L-05: empty field -> default
def test_empty_fields_fall_back_to_defaults():
    proxy = parse_uri(
        f"vless://{UUID}@example.com:443?type=&security=#Empty"
    )
    assert proxy["network"] == "tcp"
    assert proxy.get("tls") is not True
    proxy = parse_uri(_vmess_uri({
        "ps": "E", "add": "example.com", "port": 443,
        "id": UUID, "net": "", "tls": "",
    }))
    assert proxy["network"] == "tcp"
    assert proxy["tls"] is False


# ------------------------------------------------- L-13 / L-14: name rules
def test_long_name_truncated_with_warning():
    from app.uri_parser import parse_uri_with_warnings
    long_name = "N" * 100
    proxy, warnings = parse_uri_with_warnings(
        f"vless://{UUID}@example.com:443#{long_name}"
    )
    assert len(proxy["name"]) == 64
    assert proxy["name"] == "N" * 64
    assert any("truncated to 64" in w for w in warnings)


def test_empty_name_falls_back_to_generated():
    from app.uri_parser import normalize_node_name
    name = normalize_node_name("   ")
    assert name.startswith("node-")
    assert len(name) == len("node-") + 8
    assert normalize_node_name("  ok  ") == "ok"


# ------------------------------------------- H-11: validate_proxy_dict
def test_validate_proxy_dict_accepts_and_normalizes():
    from app.uri_parser import validate_proxy_dict
    proxy = validate_proxy_dict({
        "type": "SS", "server": "example.com", "port": "8388",
        "cipher": "aes-128-gcm", "password": "pw", "name": "N",
    })
    assert proxy["type"] == "ss"
    assert proxy["port"] == 8388
    assert isinstance(proxy["port"], int)


def test_validate_proxy_dict_hy2_alias_and_vmess_defaults():
    from app.uri_parser import validate_proxy_dict
    proxy = validate_proxy_dict({
        "type": "hy2", "server": "example.com", "port": 8443,
        "password": "pw",
    })
    assert proxy["type"] == "hysteria2"
    proxy = validate_proxy_dict({
        "type": "vmess", "server": "example.com", "port": 443,
        "uuid": UUID,
    })
    assert proxy["cipher"] == "auto"
    assert proxy["alterId"] == 0


@pytest.mark.parametrize("bad_proxy,match", [
    ({"type": "socks", "server": "example.com", "port": 1080},
     "unsupported proxy type"),
    ({"server": "example.com", "port": 1080}, "non-empty 'type'"),
    ({"type": "ss", "server": "example.com", "port": 99999,
      "cipher": "aes-128-gcm", "password": "pw"}, "out-of-range port"),
    ({"type": "ss", "server": "example.com", "port": 0,
      "cipher": "aes-128-gcm", "password": "pw"}, "out-of-range port"),
    ({"type": "vless", "server": "example.com", "port": 443},
     "missing the UUID"),
    ({"type": "vless", "server": "example.com", "port": 443,
      "uuid": "not-a-uuid"}, "invalid UUID"),
    ({"type": "vless", "server": "bad_host!", "port": 443, "uuid": UUID},
     "invalid server address"),
    ({"type": "ss", "server": "example.com", "port": 8388,
      "password": "pw"}, "missing the cipher"),
    ({"type": "ss", "server": "example.com", "port": 8388,
      "cipher": "bad-cipher", "password": "pw"}, "unsupported cipher"),
    ({"type": "trojan", "server": "example.com", "port": 443},
     "non-empty 'password'"),
    ({"type": "vmess", "server": "example.com", "port": 443,
      "uuid": UUID, "tls": "yes"}, "'tls' must be a boolean"),
    ({"type": "vless", "server": "example.com", "port": 443,
      "uuid": UUID, "network": "smoke"}, "unsupported network"),
])
def test_validate_proxy_dict_rejects(bad_proxy, match):
    from app.uri_parser import validate_proxy_dict
    with pytest.raises(ValueError, match=match):
        validate_proxy_dict(bad_proxy)


def test_validate_proxy_dict_missing_name_gets_fallback():
    from app.uri_parser import validate_proxy_dict
    warnings: list[str] = []
    proxy = validate_proxy_dict({
        "type": "ss", "server": "example.com", "port": 8388,
        "cipher": "aes-128-gcm", "password": "pw",
    }, warnings=warnings)
    assert proxy["name"].startswith("node-")
    assert any("empty node name" in w for w in warnings)


# ------------------------------------------------- M-19: URI masking
def test_mask_uri_for_log():
    from app.uri_parser import mask_uri_for_log
    ss_uri = (
        "ss://" + _b64("aes-128-gcm:testpass") + "@example.com:8388#Test-SS"
    )
    masked = mask_uri_for_log(ss_uri)
    assert "testpass" not in masked
    assert "aes-128-gcm" not in masked
    assert masked.startswith("ss://***@example.com:8388#Test-SS")

    trojan = "trojan://secret-pass@example.com:443#T"
    assert "secret-pass" not in mask_uri_for_log(trojan)
    assert mask_uri_for_log(trojan).startswith("trojan://***@example.com:443")

    vmess = _vmess_uri({
        "ps": "T", "add": "example.com", "port": 443,
        "id": UUID, "net": "tcp",
    })
    masked = mask_uri_for_log(vmess)
    assert UUID not in masked
    assert masked.startswith("vmess://***")

    vless = (
        f"vless://{UUID}@example.com:443"
        "?security=tls&sni=example.com#V"
    )
    masked = mask_uri_for_log(vless)
    assert UUID not in masked
    assert "sni=example.com" in masked

    assert mask_uri_for_log("not-a-uri") == "not-a-uri"
