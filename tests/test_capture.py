"""Tests for capture helpers and result serialization (no real browser)."""

from __future__ import annotations

from redeye.capture import CaptureResult, _safe_filename


def test_safe_filename_sanitizes():
    name = _safe_filename("https://example.com/a/b?x=1", 7)
    assert name.startswith("0007_")
    assert name.endswith(".png")
    # No path separators or query chars survive.
    assert "/" not in name and "?" not in name and "=" not in name


def test_safe_filename_truncates_long_urls():
    name = _safe_filename("http://" + "a" * 500, 1)
    assert len(name) <= 4 + 1 + 80 + 4  # index_ + slug + .png, generous bound


def test_capture_result_high_interest_from_tech():
    assert CaptureResult(url="x", tech=["WordPress"]).high_interest
    assert not CaptureResult(url="x", tech=["Nginx"]).high_interest


def test_capture_result_to_dict_is_json_ready():
    result = CaptureResult(url="http://x", status=200, tech=["WordPress"])
    d = result.to_dict()
    assert d["url"] == "http://x"
    assert d["status"] == 200
    assert d["high_interest"] is True
    # Every value is a JSON-native type.
    import json

    json.dumps(d)  # must not raise
