from hackertrap.web.auth import hash_password, verify_password


def test_password_hash_roundtrip():
    stored = hash_password("hunter2-trap")
    assert verify_password("hunter2-trap", stored)
    assert not verify_password("wrong", stored)
