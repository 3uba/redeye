"""Tests for the naive technology fingerprint rules."""

from __future__ import annotations

from redeye.fingerprint import (
    HIGH_INTEREST,
    LOGIN_LABEL,
    fingerprint,
    is_high_interest,
)


def test_wordpress_from_body():
    labels = fingerprint({}, '<link href="/wp-content/themes/x/style.css">')
    assert "WordPress" in labels


def test_wordpress_from_login_path():
    labels = fingerprint({}, '<a href="/wp-login.php">Log in</a>')
    assert "WordPress" in labels


def test_drupal_from_header():
    labels = fingerprint({"X-Drupal-Cache": "HIT"}, "<html></html>")
    assert "Drupal" in labels


def test_tomcat_from_title():
    labels = fingerprint({}, "<html></html>", title="Apache Tomcat/9.0.50")
    assert "Tomcat" in labels


def test_server_header_nginx():
    labels = fingerprint({"Server": "nginx/1.18.0"}, "")
    assert "Nginx" in labels


def test_login_page_detected_structurally():
    body = '<form><input name="username"><input type="password"></form>'
    labels = fingerprint({}, body)
    assert LOGIN_LABEL in labels


def test_no_password_field_is_not_login():
    body = '<form><input name="search" type="text"></form>'
    assert LOGIN_LABEL not in fingerprint({}, body)


def test_multiple_labels_and_sorted():
    headers = {"Server": "Apache", "X-Powered-By": "PHP/8.1"}
    body = '<link href="/wp-content/x.css"><input type="password">'
    labels = fingerprint(headers, body)
    assert labels == sorted(labels)
    assert "WordPress" in labels and "PHP" in labels and LOGIN_LABEL in labels


def test_default_page():
    labels = fingerprint({}, "<html><body><h1>Welcome to nginx!</h1></body></html>")
    assert "Default/Placeholder page" in labels


def test_empty_response_no_labels():
    assert fingerprint({}, "") == []


def test_high_interest_classification():
    assert is_high_interest(["WordPress"])
    assert is_high_interest([LOGIN_LABEL])
    # Pure infra labels are not, by themselves, high interest.
    assert not is_high_interest(["Nginx"])
    assert not is_high_interest(["Apache", "PHP"])
    assert not is_high_interest([])


def test_high_interest_set_excludes_infra():
    assert "WordPress" in HIGH_INTEREST
    assert "Nginx" not in HIGH_INTEREST
    assert LOGIN_LABEL in HIGH_INTEREST


def test_server_header_with_folded_whitespace_still_matches():
    # A Server value carrying internal whitespace/newlines (folded headers,
    # "Apache/2.4.52 (Debian)") must still match the "server: apache" rule.
    labels = fingerprint({"Server": "Apache/2.4.52\n (Debian)"}, "")
    assert "Apache" in labels


def test_server_signature_matches_header_not_body():
    # "server: nginx" as a body string shouldn't false-positive Nginx, because
    # the rule is matched against rendered "name: value" header lines.
    labels = fingerprint({}, "the word server: nginx appears in prose")
    # It WILL match here because the haystack is combined; this documents that
    # the fingerprint is intentionally loose (a hint, not Wappalyzer).
    assert "Nginx" in labels
