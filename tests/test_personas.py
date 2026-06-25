from hackertrap.config import load_config
from hackertrap.personas import PERSONAS, apply_persona, build_decoy_page, avahi_service_xml


def test_apply_persona_sets_ports_and_hostname(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg = load_config()
    cfg._config_path = cfg_path

    apply_persona(cfg, "nas-backup")
    assert cfg.honeypot.persona == "nas-backup"
    assert cfg.honeypot.hostname == "nas-backup"
    assert cfg.honeypot.ports["http"] == 80
    assert cfg.honeypot.ports["smb"] == 445


def test_build_decoy_page_includes_persona_title():
    html = build_decoy_page("nas-backup", "nas-backup")
    assert "DiskStation" in html
    assert "Sign in" in html.lower() or "username" in html.lower()


def test_avahi_xml_uses_persona_not_hackertrap():
    cfg = load_config()
    cfg.setup_complete = True
    apply_persona(cfg, "accountserver")
    xml = avahi_service_xml(cfg)
    assert "Accounting Server" in xml
    assert "HackerTrap" not in xml
    assert "_smb._tcp" in xml


def test_all_personas_exist():
    assert len(PERSONAS) >= 3
    for pid in ("accountserver", "nas-backup", "print-spooler"):
        assert pid in PERSONAS
