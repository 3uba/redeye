"""Tests for report logic: status colors and grouping."""

from __future__ import annotations

import json

from redeye.capture import CaptureResult
from redeye.report import (
    group_results,
    render_report,
    status_color,
    status_label,
)


def r(**kwargs) -> CaptureResult:
    return CaptureResult(**{"url": "http://x", **kwargs})


def test_status_color_classes():
    assert status_color(r(status=200)) == "green"
    assert status_color(r(status=204)) == "green"
    assert status_color(r(status=301)) == "cyan"
    assert status_color(r(status=404)) == "yellow"
    assert status_color(r(status=500)) == "red"


def test_timeout_and_error_are_red():
    assert status_color(r(outcome="timeout")) == "red"
    assert status_color(r(outcome="error", error="boom")) == "red"


def test_unknown_status_is_grey():
    assert status_color(r(status=None, outcome="ok")) == "grey"


def test_falls_back_to_http_status_when_browser_blank():
    assert status_color(r(status=None, http_status=200)) == "green"


def test_status_label():
    assert status_label(r(status=200)) == "200"
    assert status_label(r(outcome="timeout")) == "timeout"
    assert status_label(r(outcome="error", error="connection refused")) \
        == "connection refused"


def test_grouping_high_interest_first():
    results = [
        r(url="http://plain", status=200, tech=[]),
        r(url="http://wp", status=200, tech=["WordPress"]),
        r(url="http://nginx", status=200, tech=["Nginx"]),
    ]
    groups = group_results(results)
    assert groups[0]["title"] == "High interest"
    assert groups[0]["anchor"] == "high-interest"
    # WordPress host is in High interest; nginx host is in a Nginx group; plain
    # host is in Other.
    titles = [g["title"] for g in groups]
    assert "High interest" in titles
    assert "Nginx" in titles
    assert "Other" in titles
    assert titles.index("High interest") == 0
    assert titles.index("Other") == len(titles) - 1


def test_each_host_appears_once():
    results = [r(url="http://wp", status=200, tech=["WordPress", "PHP"])]
    groups = group_results(results)
    total_cards = sum(len(g["cards"]) for g in groups)
    assert total_cards == 1  # not double-counted across WordPress and PHP


def test_render_writes_html_and_json(tmp_path):
    results = [
        r(url="http://wp", status=200, title="Blog", server="Apache",
          tech=["WordPress"], screenshot="screens/0001_wp.png"),
        r(url="http://dead", outcome="timeout"),
    ]
    report_path = render_report(results, tmp_path)
    assert report_path.exists()
    html = report_path.read_text()
    assert "redeye" in html
    assert "WordPress" in html
    assert "High interest" in html
    assert "timeout" in html

    data = json.loads((tmp_path / "results.json").read_text())
    assert data["total"] == 2
    assert data["results"][0]["tech"] == ["WordPress"]
    assert data["results"][0]["high_interest"] is True
    assert data["results"][1]["outcome"] == "timeout"


def test_render_escapes_html_in_title(tmp_path):
    results = [r(url="http://x", status=200, title="<script>alert(1)</script>")]
    report_path = render_report(results, tmp_path)
    html = report_path.read_text()
    # Jinja autoescape must neutralize the injected markup.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- enriched recon fields -------------------------------------------------


def test_missing_security_headers():
    from redeye.report import _missing_security_headers

    sec = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "missing",
        "x-frame-options": "missing",
    }
    missing = _missing_security_headers(sec)
    assert "CSP" in missing
    assert "X-Frame" in missing
    assert "HSTS" not in missing  # present, so not listed


def test_tls_summary():
    from redeye.report import _tls_summary

    assert _tls_summary({}) == ""
    s = _tls_summary({"protocol": "TLS 1.3", "issuer": "CN=Let's Encrypt, O=x"})
    assert "TLS 1.3" in s
    assert "Let's Encrypt" in s
    assert _tls_summary({"self_signed": True, "protocol": "TLS 1.2"}) \
        == "TLS 1.2 · self-signed"


def test_status_distribution():
    from redeye.report import _status_distribution

    results = [
        r(url="http://a", status=200),
        r(url="http://b", status=200),
        r(url="http://c", status=404),
        r(url="http://d", outcome="timeout"),
    ]
    dist = _status_distribution(results)
    by_color = {d["color"]: d["count"] for d in dist}
    assert by_color["green"] == 2
    assert by_color["yellow"] == 1
    assert by_color["red"] == 1  # timeout counts as red
    # percentages sum to ~100
    assert abs(sum(d["pct"] for d in dist) - 100) < 0.5


def test_to_dict_includes_enriched_fields():
    result = CaptureResult(
        url="https://x", status=200, elapsed_ms=42.37,
        security_headers={"x-frame-options": "missing"},
        tls={"issuer": "CN=X", "self_signed": True},
        redirects=[{"status": "302", "url": "http://x"}],
        ip="1.2.3.4", content_type="text/html", favicon_hash="abc123",
    )
    d = result.to_dict()
    assert d["elapsed_ms"] == 42.4  # rounded to 1dp
    assert d["security_headers"] == {"x-frame-options": "missing"}
    assert d["tls"]["self_signed"] is True
    assert d["redirects"][0]["status"] == "302"
    assert d["ip"] == "1.2.3.4"
    assert d["favicon_hash"] == "abc123"
    # still JSON-serializable
    json.dumps(d)


def test_host_property():
    assert CaptureResult(url="https://example.com:8443/path").host == "example.com:8443"
    # falls back to final_url when present
    res = CaptureResult(url="http://a", final_url="https://b.com/x")
    assert res.host == "b.com"
