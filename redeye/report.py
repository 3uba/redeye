"""Assemble the self-contained HTML report and results.json."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .capture import CaptureResult
from .template import REPORT_TEMPLATE


def status_color(result: CaptureResult) -> str:
    """Map a result to a CSS color class: green/cyan/yellow/red/grey.

    2xx green, 3xx cyan, 4xx yellow, 5xx and timeout/error red, unknown grey.
    """
    if result.outcome == "timeout":
        return "red"
    if result.outcome == "error":
        return "red"
    status = result.status if result.status is not None else result.http_status
    if status is None:
        return "grey"
    if 200 <= status < 300:
        return "green"
    if 300 <= status < 400:
        return "cyan"
    if 400 <= status < 500:
        return "yellow"
    if 500 <= status < 600:
        return "red"
    return "grey"


def status_label(result: CaptureResult) -> str:
    """Human-readable status text for a card."""
    if result.outcome == "timeout":
        return "timeout"
    if result.outcome == "error":
        return result.error or "error"
    status = result.status if result.status is not None else result.http_status
    return str(status) if status is not None else "?"


def _tls_summary(tls: dict) -> str:
    """One-line TLS summary for a card, or '' when there's nothing to show."""
    if not tls:
        return ""
    parts = []
    if tls.get("protocol"):
        parts.append(str(tls["protocol"]))
    if tls.get("self_signed"):
        parts.append("self-signed")
    elif tls.get("issuer"):
        issuer = str(tls["issuer"])
        parts.append(issuer.split(",")[0][:40])
    return " · ".join(parts)


def _missing_security_headers(sec: dict) -> list[str]:
    """Short names of the notable security headers that are absent."""
    short = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame",
        "x-content-type-options": "X-Content-Type",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    return [short.get(k, k) for k, v in sec.items() if v == "missing"]


def _card_data(result: CaptureResult) -> dict:
    """Flatten a CaptureResult into the template's card dict."""
    status = result.status if result.status is not None else result.http_status
    missing = _missing_security_headers(result.security_headers)
    return {
        "url": result.url,
        "final_url": result.final_url or result.url,
        "host": result.host,
        "status": status,
        "status_label": status_label(result),
        "color": status_color(result),
        "title": result.title,
        "server": result.server,
        "tech": result.tech,
        "screenshot": result.screenshot,
        "error": result.error,
        "outcome": result.outcome,
        "high_interest": result.high_interest,
        "elapsed_ms": round(result.elapsed_ms) if result.elapsed_ms else None,
        "content_type": result.content_type,
        "ip": result.ip,
        "tls_summary": _tls_summary(result.tls),
        "tls": result.tls,
        "redirects": result.redirects,
        "security_headers": result.security_headers,
        "missing_security": missing,
        "headers": result.headers,
        "favicon_hash": result.favicon_hash,
        # a lower-cased blob the JS filter searches
        "search": " ".join(
            [result.url, result.final_url, result.title, result.server, *result.tech]
        ).lower(),
    }


def group_results(results: list[CaptureResult]) -> list[dict]:
    """Group results so the interesting stuff floats up.

    "High interest" first (known apps / login pages), then one section per tech
    tag, then an "Other" catch-all. A host appears once, in its strongest
    group -- high-interest if it qualifies, else its first tech tag, else Other.
    """
    high: list[dict] = []
    by_tag: dict[str, list[dict]] = {}
    other: list[dict] = []

    for result in results:
        card = _card_data(result)
        if result.high_interest:
            high.append(card)
        elif result.tech:
            by_tag.setdefault(result.tech[0], []).append(card)
        else:
            other.append(card)

    groups: list[dict] = []
    if high:
        groups.append({"title": "High interest", "anchor": "high-interest",
                       "hot": True, "cards": high})
    for tag in sorted(by_tag):
        anchor = "tag-" + "".join(c if c.isalnum() else "-" for c in tag.lower())
        groups.append({"title": tag, "anchor": anchor, "hot": False,
                       "cards": by_tag[tag]})
    if other:
        groups.append({"title": "Other", "anchor": "other", "hot": False,
                       "cards": other})
    return groups


def _status_distribution(results: list[CaptureResult]) -> list[dict]:
    """Count results by status class, for the console bar meter."""
    buckets = {"green": 0, "cyan": 0, "yellow": 0, "red": 0, "grey": 0}
    for r in results:
        buckets[status_color(r)] += 1
    labels = {"green": "2xx", "cyan": "3xx", "yellow": "4xx",
              "red": "5xx / err", "grey": "?"}
    total = max(1, len(results))
    return [
        {"color": c, "label": labels[c], "count": n, "pct": round(n / total * 100, 1)}
        for c, n in buckets.items() if n
    ]


def render_report(results: list[CaptureResult], output_dir: Path) -> Path:
    """Write ``report.html`` and ``results.json`` into *output_dir*.

    Returns the path to the written HTML report.
    """
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(REPORT_TEMPLATE)

    groups = group_results(results)
    high_count = sum(1 for r in results if r.high_interest)
    ok_count = sum(1 for r in results if r.outcome == "ok")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = template.render(
        groups=groups,
        total=len(results),
        high_count=high_count,
        ok_count=ok_count,
        distribution=_status_distribution(results),
        generated=generated,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")

    results_path = output_dir / "results.json"
    results_path.write_text(
        json.dumps(
            {
                "generated": generated,
                "total": len(results),
                "results": [r.to_dict() for r in results],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return report_path
