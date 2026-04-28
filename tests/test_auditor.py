import pytest
import datetime
import sys
import os

# add src/ to the path so we can import auditor.py directly
# without this, Python can't find auditor.py from the tests/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auditor import evaluate_results, WEAK_PROTOCOLS, WEAK_CIPHERS


def test_evaluate_clean_server_passes():
    """
    Happy path: a server with modern TLS 1.3 and a strong cipher
    should pass evaluation with no issues detected.
    """
    # fake scan data mimicking what scan_host() would return for a clean server
    scan = {
        "hostname": "example.com",
        "port": 443,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cert_subject": "example.com",
        "cert_issuer": "DigiCert Inc",
        "cert_expiry": "UNKNOWN",
        "timestamp": "2026-04-27T00:00:00+00:00"
    }

    result = evaluate_results(scan)

    assert result["passed"] == True          # clean server must pass
    assert result["protocol_weak"] == False  # TLS 1.3 is not weak
    assert result["cipher_weak"] == False    # AES-256-GCM is not weak
    assert result["issues"] == []            # no issues should be reported


def test_evaluate_weak_cipher_fails():
    """
    Negative test: a server offering a weak cipher suite
    should fail evaluation and report the issue.
    """
    # fake scan data mimicking our weak test server
    scan = {
        "hostname": "weak.example.com",
        "port": 8443,
        "protocol": "TLSv1.2",
        "cipher": "AES128-SHA",
        "cert_subject": "weak.example.com",
        "cert_issuer": "Test CA",
        "cert_expiry": "UNKNOWN",
        "timestamp": "2026-04-27T00:00:00+00:00"
    }

    result = evaluate_results(scan)

    assert result["passed"] == False         # weak server must fail
    assert result["cipher_weak"] == True     # cipher check must have triggered
    assert len(result["issues"]) > 0         # issues list must not be empty
    # verify the right cipher was flagged, not just any issue
    assert any("AES128-SHA" in issue for issue in result["issues"])


def test_evaluate_weak_protocol_fails():
    """
    Edge case: a server using a deprecated protocol version (TLS 1.1)
    should fail evaluation even if the cipher looks acceptable.
    """
    scan = {
        "hostname": "old.example.com",
        "port": 8443,
        "protocol": "TLSv1.1",  # deprecated protocol
        "cipher": "AES256-SHA",  # cipher itself is not in weak list
        "cert_subject": "old.example.com",
        "cert_issuer": "Test CA",
        "cert_expiry": "UNKNOWN",
        "timestamp": "2026-04-27T00:00:00+00:00"
    }

    result = evaluate_results(scan)

    assert result["passed"] == False         # must fail due to weak protocol
    assert result["protocol_weak"] == True   # protocol check must have triggered
    assert any("TLSv1.1" in issue for issue in result["issues"])


def test_evaluate_expired_certificate_fails():
    """
    Edge case: a server with an expired certificate should be flagged
    even if the protocol and cipher are both strong.
    """
    scan = {
        "hostname": "expired.example.com",
        "port": 443,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cert_subject": "expired.example.com",
        "cert_issuer": "DigiCert Inc",
        "cert_expiry": "Jan 01 00:00:00 2020 GMT",  # expired in 2020
        "timestamp": "2026-04-27T00:00:00+00:00"
    }

    result = evaluate_results(scan)

    assert result["passed"] == False         # must fail due to expired cert
    assert result["cert_expired"] == True    # cert expiry check must have triggered
    assert any("expired" in issue.lower() for issue in result["issues"])


def test_evaluate_multiple_issues_detected():
    """
    Edge case: a server with both a weak protocol AND a weak cipher
    should report both issues, not just one.
    """
    scan = {
        "hostname": "terrible.example.com",
        "port": 8443,
        "protocol": "TLSv1.1",  # weak protocol
        "cipher": "AES128-SHA",  # weak cipher
        "cert_subject": "terrible.example.com",
        "cert_issuer": "Test CA",
        "cert_expiry": "UNKNOWN",
        "timestamp": "2026-04-27T00:00:00+00:00"
    }

    result = evaluate_results(scan)

    assert result["passed"] == False         # must fail
    assert result["protocol_weak"] == True   # protocol flagged
    assert result["cipher_weak"] == True     # cipher flagged
    assert len(result["issues"]) >= 2        # both issues must be reported


def test_weak_protocols_set_contains_expected_values():
    """
    Edge case: verify the WEAK_PROTOCOLS constant contains
    the expected deprecated versions and not modern ones.
    """
    # these must be in the weak list
    assert "TLSv1" in WEAK_PROTOCOLS
    assert "TLSv1.1" in WEAK_PROTOCOLS
    assert "SSLv2" in WEAK_PROTOCOLS
    assert "SSLv3" in WEAK_PROTOCOLS

    # these must NOT be in the weak list
    assert "TLSv1.2" not in WEAK_PROTOCOLS
    assert "TLSv1.3" not in WEAK_PROTOCOLS


def test_weak_ciphers_set_contains_expected_values():
    """
    Edge case: verify the WEAK_CIPHERS constant contains
    known broken ciphers and not modern strong ones.
    """
    # these must be in the weak list
    assert "RC4" in WEAK_CIPHERS
    assert "DES" in WEAK_CIPHERS
    assert "NULL" in WEAK_CIPHERS
    assert "AES128-SHA" in WEAK_CIPHERS

    # these must NOT be in the weak list
    assert "AES256-GCM-SHA384" not in WEAK_CIPHERS
    assert "CHACHA20-POLY1305" not in WEAK_CIPHERS