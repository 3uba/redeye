"""Assemble the self-contained HTML report and results.json."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .capture import CaptureResult


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


@dataclass
class ReportGroup:
    """A titled section of cards in the report."""

    title: str
    anchor: str
    cards: list[dict]


def _card_data(result: CaptureResult) -> dict:
    """Flatten a CaptureResult into the template's card dict."""
    return {
        "url": result.url,
        "final_url": result.final_url or result.url,
        "status_label": status_label(result),
        "color": status_color(result),
        "title": result.title,
        "server": result.server,
        "tech": result.tech,
        "screenshot": result.screenshot,
        "error": result.error,
        "high_interest": result.high_interest,
        # a lower-cased blob the JS filter searches
        "search": " ".join(
            [result.url, result.final_url, result.title, result.server, *result.tech]
        ).lower(),
    }


def group_results(results: list[CaptureResult]) -> list[ReportGroup]:
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

    groups: list[ReportGroup] = []
    if high:
        groups.append(ReportGroup("High interest", "high-interest", high))
    for tag in sorted(by_tag):
        anchor = "tag-" + "".join(c if c.isalnum() else "-" for c in tag.lower())
        groups.append(ReportGroup(tag, anchor, by_tag[tag]))
    if other:
        groups.append(ReportGroup("Other", "other", other))
    return groups


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redeye report — {{ generated }}</title>
<style>
  :root {
    --bg: #0f1216; --panel: #171b21; --fg: #e6e9ee; --muted: #8b94a3;
    --border: #262c36; --green: #3fb950; --cyan: #39c5cf; --yellow: #d29922;
    --red: #f85149; --grey: #6e7681; --accent: #e5534b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  header {
    position: sticky; top: 0; z-index: 10; background: var(--panel);
    border-bottom: 1px solid var(--border); padding: 14px 20px;
    display: flex; gap: 16px; align-items: center; flex-wrap: wrap;
  }
  header h1 { font-size: 16px; margin: 0; letter-spacing: .3px; }
  header h1 .eye { color: var(--accent); }
  .meta { color: var(--muted); font-size: 12px; }
  #filter {
    margin-left: auto; background: var(--bg); border: 1px solid var(--border);
    color: var(--fg); padding: 7px 11px; border-radius: 7px; min-width: 240px;
    font-size: 13px;
  }
  #filter:focus { outline: none; border-color: var(--accent); }
  main { padding: 20px; }
  section { margin-bottom: 28px; }
  .section-title {
    font-size: 13px; text-transform: uppercase; letter-spacing: .8px;
    color: var(--muted); margin: 0 0 12px; display: flex; gap: 8px;
    align-items: center;
  }
  .section-title .count {
    background: var(--border); color: var(--fg); border-radius: 10px;
    padding: 1px 8px; font-size: 11px;
  }
  .section-title.hot { color: var(--accent); }
  .grid {
    display: grid; gap: 14px;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; overflow: hidden; display: flex; flex-direction: column;
  }
  .card.hot { border-color: var(--accent); }
  .shot { aspect-ratio: 16 / 10; background: #0b0d10; overflow: hidden;
          border-bottom: 1px solid var(--border); }
  .shot a { display: block; height: 100%; }
  .shot img { width: 100%; height: 100%; object-fit: cover; object-position: top;
              display: block; }
  .shot .noshot { display: flex; align-items: center; justify-content: center;
                  height: 100%; color: var(--grey); font-size: 12px; }
  .body { padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; }
  .url { font-size: 13px; word-break: break-all; }
  .url a { color: var(--fg); text-decoration: none; }
  .url a:hover { color: var(--accent); }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
         font-size: 12px; color: var(--muted); }
  .status { font-weight: 600; }
  .status.green { color: var(--green); } .status.cyan { color: var(--cyan); }
  .status.yellow { color: var(--yellow); } .status.red { color: var(--red); }
  .status.grey { color: var(--grey); }
  .title { color: var(--fg); font-size: 12px; max-height: 2.8em; overflow: hidden; }
  .tags { display: flex; gap: 5px; flex-wrap: wrap; }
  .tag { background: var(--border); color: var(--fg); border-radius: 5px;
         padding: 1px 7px; font-size: 11px; }
  .tag.hot { background: var(--accent); color: #fff; }
  .empty { color: var(--grey); padding: 40px; text-align: center; }
  footer { color: var(--muted); font-size: 12px; padding: 16px 20px;
           border-top: 1px solid var(--border); }
</style>
</head>
<body>
<header>
  <h1><span class="eye">●</span> redeye</h1>
  <span class="meta">{{ total }} targets · {{ high_count }} high interest · {{ generated }}</span>
  <input id="filter" type="search" placeholder="filter by url, title, tag…"
         autocomplete="off" aria-label="filter cards">
</header>
<main id="report">
  {% for group in groups %}
  <section data-group>
    <h2 class="section-title {% if group.anchor == 'high-interest' %}hot{% endif %}">
      {{ group.title }} <span class="count">{{ group.cards|length }}</span>
    </h2>
    <div class="grid">
      {% for card in group.cards %}
      <article class="card {% if card.high_interest %}hot{% endif %}"
               data-search="{{ card.search }}">
        <div class="shot">
          {% if card.screenshot %}
          <a href="{{ card.screenshot }}" target="_blank" rel="noopener">
            <img loading="lazy" src="{{ card.screenshot }}" alt="screenshot of {{ card.url }}">
          </a>
          {% else %}
          <div class="noshot">no screenshot</div>
          {% endif %}
        </div>
        <div class="body">
          <div class="url">
            <a href="{{ card.final_url }}" target="_blank" rel="noopener">{{ card.url }}</a>
          </div>
          <div class="row">
            <span class="status {{ card.color }}">{{ card.status_label }}</span>
            {% if card.server %}<span>· {{ card.server }}</span>{% endif %}
          </div>
          {% if card.title %}<div class="title">{{ card.title }}</div>{% endif %}
          {% if card.tech %}
          <div class="tags">
            {% for tag in card.tech %}
            <span class="tag {% if card.high_interest %}hot{% endif %}">{{ tag }}</span>
            {% endfor %}
          </div>
          {% endif %}
        </div>
      </article>
      {% endfor %}
    </div>
  </section>
  {% endfor %}
  <div class="empty" id="no-results" style="display:none">no cards match your filter</div>
</main>
<footer>
  Generated by redeye. Only scan targets you are authorized to test.
</footer>
<script>
  // Plain-JS filter: hide non-matching cards and empty sections, no build step.
  const input = document.getElementById('filter');
  const cards = Array.from(document.querySelectorAll('.card'));
  const sections = Array.from(document.querySelectorAll('[data-group]'));
  const noResults = document.getElementById('no-results');
  function apply() {
    const q = input.value.trim().toLowerCase();
    let anyVisible = false;
    for (const card of cards) {
      const hit = !q || card.dataset.search.includes(q);
      card.style.display = hit ? '' : 'none';
      if (hit) anyVisible = true;
    }
    for (const section of sections) {
      const visible = section.querySelectorAll('.card:not([style*="none"])').length;
      section.style.display = visible ? '' : 'none';
    }
    noResults.style.display = anyVisible ? 'none' : '';
  }
  input.addEventListener('input', apply);
</script>
</body>
</html>
"""


def render_report(results: list[CaptureResult], output_dir: Path) -> Path:
    """Write ``report.html`` and ``results.json`` into *output_dir*.

    Returns the path to the written HTML report.
    """
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_TEMPLATE)

    groups = group_results(results)
    high_count = sum(1 for r in results if r.high_interest)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = template.render(
        groups=groups,
        total=len(results),
        high_count=high_count,
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
