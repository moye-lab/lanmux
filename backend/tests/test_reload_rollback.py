"""Safe reload + rollback tests (real ConfigService, fake client).

The mihomo client is faked (no network, no mihomo binary); the file
pipeline — compile, validate, tmp write, backup, atomic replace,
reload, rollback — is the real one.
"""

import pytest
import yaml

from app.config_service import (
    ConfigApplyError,
    ConfigService,
    mask_config_text,
    validate_config_dict,
    validate_config_yaml,
)
from app.database import Database
from app.mihomo_client import MihomoError


class FakeClient:
    """Records reload calls.

    ``fail=True`` makes every reload raise (mihomo down).
    ``fail_times=N`` makes the next N reloads raise, then succeed —
    the transient case (mihomo rejects the new config but accepts the
    restored one).
    """

    def __init__(self, fail=False):
        self.fail = fail
        self.fail_times = 0
        self.reload_calls = 0

    def reload_config(self, force=True):
        self.reload_calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise MihomoError(
                "mihomo API error (PUT /configs): bad config", status=400
            )
        if self.fail:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )


@pytest.fixture
def db(tmp_path):
    handle = Database(tmp_path / "lanmux.db")
    handle.set_setting("ss_password", "fake-ss-pass")
    handle.set_setting("mihomo_secret", "fake-mihomo-secret")
    yield handle
    handle.close()


@pytest.fixture
def service(db, tmp_path):
    client = FakeClient()
    handle = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml", lambda: client
    )
    handle._fake_client = client  # test handle, not production API
    return handle


def test_apply_success_writes_valid_config(service):
    service.apply()
    text = service.config_path.read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    assert config["proxy-groups"][0]["name"] == "YouTube"
    assert config["proxy-groups"][0]["proxies"] == ["DIRECT"]  # cold start
    assert config["secret"] == "fake-mihomo-secret"
    assert service._fake_client.reload_calls == 1
    assert service.db.get_setting("last_apply_ok") == "1"


def test_apply_backs_up_previous_config(service, db):
    service.apply()
    first_text = service.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)
    service.apply()
    bak = service.config_path.with_suffix(".yaml.bak")
    assert bak.read_text(encoding="utf-8") == first_text
    assert "10002" in service.config_path.read_text(encoding="utf-8")
    assert service._fake_client.reload_calls == 2


def test_reload_failure_restores_backup(service, db):
    service.apply()
    good_text = service.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)

    # Transient failure: the new config is rejected, the restored
    # backup reloads fine.
    service._fake_client.fail_times = 1
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    error = exc_info.value
    assert error.stage == "reload"
    assert error.rolled_back is True
    assert "reload failed" in error.message
    # The live file is the previous good config, not the new one.
    assert service.config_path.read_text(encoding="utf-8") == good_text
    # Reload was attempted for the new config, then again for the
    # restored backup (plus the first successful apply).
    assert service._fake_client.reload_calls == 3
    assert service.db.get_setting("last_apply_ok") == "0"
    assert "reload failed" in service.db.get_setting("last_apply_error")


def test_reload_failure_without_previous_config_removes_new_file(service):
    service._fake_client.fail = True
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.rolled_back is True
    assert not service.config_path.exists()
    # No rollback reload is attempted when there was nothing to restore.
    assert service._fake_client.reload_calls == 1


def test_rollback_reload_failure_reported(service, db):
    """File restored but the second reload fails: rolled_back True.

    The on-disk config is the previous good one; only the live reload
    of it failed (mihomo unreachable). The error must say the file was
    restored — never "rollback also failed".
    """
    service.apply()
    good_text = service.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)
    service._fake_client.fail = True
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    # _rollback restores the file, then its reload fails too.
    assert exc_info.value.rolled_back is True
    assert "file restored" in exc_info.value.message
    assert "rollback also failed" not in exc_info.value.message
    assert service.config_path.read_text(encoding="utf-8") == good_text
    # First apply (1) + new-config reload (1) + rollback reload (1).
    assert service._fake_client.reload_calls == 3


def test_compile_failure_writes_nothing(service, db):
    db.set_setting("mihomo_secret", "")  # required secret unset
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "compile"
    assert not service.config_path.exists()
    assert service._fake_client.reload_calls == 0


def test_validate_config_dict_rejects_missing_sections():
    with pytest.raises(ValueError, match="missing required section"):
        validate_config_dict({"proxies": []})
    with pytest.raises(ValueError, match="not a list"):
        validate_config_dict({
            "proxies": {}, "proxy-groups": [], "rules": [],
            "listeners": [], "dns": {}, "secret": "x",
        })
    validate_config_dict({  # minimal valid shape passes
        "proxies": [], "proxy-groups": [], "rules": [],
        "listeners": [], "dns": {}, "secret": "x",
    })


def test_validate_config_yaml_rejects_garbage():
    with pytest.raises(ValueError, match="does not parse"):
        validate_config_yaml(":\n - [\n")
    with pytest.raises(ValueError, match="missing required section"):
        validate_config_yaml("proxies: []\n")


def test_mask_config_text_masks_secrets_only():
    text = (
        "secret: fake-mihomo-secret\n"
        "listeners:\n"
        "  - {name: lan-ss, password: fake-ss-pass, port: 10001}\n"
        "proxies:\n"
        "  - {name: N1, type: vless, server: example.com, port: 443,"
        " uuid: fake-uuid-1234, password: fake-proxy-pass}\n"
    )
    masked = mask_config_text(text)
    assert "fake-mihomo-secret" not in masked
    assert "fake-ss-pass" not in masked
    assert "fake-uuid-1234" not in masked
    assert "fake-proxy-pass" not in masked
    # L-23: long secrets keep first/last 2 chars, middle masked.
    assert "fa****et" in masked  # fake-mihomo-secret
    assert "fa****ss" in masked  # fake-ss-pass / fake-proxy-pass
    assert "fa****34" in masked  # fake-uuid-1234
    assert masked.count("****") == 4
    assert "example.com" in masked  # non-secrets survive
    assert "10001" in masked
