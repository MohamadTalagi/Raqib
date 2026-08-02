from policies.catalog.pqc_crypto_reference import (
    TIP_CERT_SIGNATURE_FAIL,
    TIP_FIRMWARE_CRYPTO_FAIL,
    TIP_FIRMWARE_CRYPTO_UNKNOWN,
    TIP_TLS_KEY_EXCHANGE_FAIL,
    _parse_version,
    firmware_crypto_pqc_status,
)


def test_parse_version_extracts_leading_digit_groups():
    assert _parse_version("3.5.6") == (3, 5, 6)
    assert _parse_version("1.0.1e") == (1, 0, 1)
    assert _parse_version("3") == (3,)


def test_parse_version_returns_none_for_unparseable_string():
    assert _parse_version("unknown") is None
    assert _parse_version("") is None


def test_firmware_crypto_pqc_status_pass_for_recent_openssl():
    assert firmware_crypto_pqc_status("openssl", "3.5.6") == "pass"
    assert firmware_crypto_pqc_status("OpenSSL", "3.2.0") == "pass"  # case-insensitive, exact threshold


def test_firmware_crypto_pqc_status_fail_for_old_openssl():
    assert firmware_crypto_pqc_status("openssl", "1.0.1e") == "fail"


def test_firmware_crypto_pqc_status_unknown_for_unrecognized_library():
    assert firmware_crypto_pqc_status("wolfssl", "5.6.4") == "unknown"
    assert firmware_crypto_pqc_status("busybox", "1.19.4") == "unknown"


def test_firmware_crypto_pqc_status_unknown_for_unparseable_version():
    assert firmware_crypto_pqc_status("openssl", "unknown") == "unknown"


def test_tips_are_non_empty_fixed_strings():
    for tip in (TIP_TLS_KEY_EXCHANGE_FAIL, TIP_CERT_SIGNATURE_FAIL, TIP_FIRMWARE_CRYPTO_FAIL, TIP_FIRMWARE_CRYPTO_UNKNOWN):
        assert isinstance(tip, str)
        assert len(tip) > 20
