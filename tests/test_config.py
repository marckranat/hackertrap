from hackertrap.config import _as_dict, load_config, save_config
from hackertrap.web.auth import set_password


def test_as_dict_handles_null():
    assert _as_dict(None) == {}
    assert _as_dict({"a": 1}) == {"a": 1}


def test_password_hash_yaml_roundtrip(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg = load_config()
    cfg._config_path = cfg_path
    set_password(cfg, "longpassword123")
    save_config(cfg)

    reloaded = load_config(cfg_path)
    assert reloaded.web.admin_password_hash.startswith("pbkdf2_sha256$")
    assert reloaded.system.repo_url
