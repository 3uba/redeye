"""Tests for input normalization: url file, single, and Nmap XML parsing."""

from __future__ import annotations

import pytest

from redeye.inputs import (
    InputError,
    Target,
    collect_targets,
    dedupe,
    from_file,
    from_nmap_xml,
    normalize_host_entry,
)

# --- bare-host / url normalization ----------------------------------------


def test_full_url_passthrough():
    t = normalize_host_entry("https://example.com/path")
    assert t.url == "https://example.com/path"
    assert not t.needs_probe


def test_blank_and_comment_lines_ignored():
    assert normalize_host_entry("") is None
    assert normalize_host_entry("   ") is None
    assert normalize_host_entry("# a comment") is None


def test_bare_host_auto_guesses_https_with_probe():
    t = normalize_host_entry("example.com", "auto")
    assert t.url == "https://example.com"
    assert t.needs_probe is True


def test_tls_port_forces_https_no_probe():
    t = normalize_host_entry("10.0.0.1:8443", "auto")
    assert t.url == "https://10.0.0.1:8443"
    assert t.needs_probe is False


def test_plain_port_forces_http():
    t = normalize_host_entry("10.0.0.1:8080", "auto")
    assert t.url == "http://10.0.0.1:8080"
    assert t.needs_probe is False


def test_explicit_scheme_override():
    assert normalize_host_entry("example.com", "http").url == "http://example.com"
    assert normalize_host_entry("example.com", "https").url == "https://example.com"


# --- file reading ---------------------------------------------------------


def test_from_file(tmp_path):
    p = tmp_path / "urls.txt"
    p.write_text("# comment\nhttps://a.com\nb.com:8080\n\n")
    targets = from_file(p)
    urls = [t.url for t in targets]
    assert urls == ["https://a.com", "http://b.com:8080"]


def test_from_file_missing():
    with pytest.raises(InputError, match="no such file"):
        from_file(__import__("pathlib").Path("/nope/nope.txt"))


def test_from_file_empty(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_text("# only comments\n\n")
    with pytest.raises(InputError, match="no usable targets"):
        from_file(p)


# --- Nmap XML parsing ------------------------------------------------------

_NMAP = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.lab" type="PTR"/></hostnames>
    <ports>
      <port portid="80"><state state="open"/><service name="http"/></port>
      <port portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port>
      <port portid="22"><state state="open"/><service name="ssh"/></port>
      <port portid="8080"><state state="closed"/><service name="http-proxy"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_nmap_extracts_web_ports_with_hostname(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(_NMAP)
    urls = sorted(t.url for t in from_nmap_xml(p))
    # hostname preferred over IP; 80 -> http (no port shown), 443 -> https ssl.
    assert urls == ["http://web.lab", "https://web.lab"]


def test_nmap_skips_down_host_closed_ports_and_ssh(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(_NMAP)
    urls = [t.url for t in from_nmap_xml(p)]
    assert "ssh" not in str(urls)
    assert all("10.0.0.9" not in u for u in urls)  # down host skipped
    assert all(":8080" not in u for u in urls)      # closed port skipped


def test_nmap_http_named_nonstandard_port(tmp_path):
    xml = """<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
      <address addr="1.2.3.4" addrtype="ipv4"/>
      <ports>
        <port portid="5000"><state state="open"/>
          <service name="http-alt"/></port>
      </ports>
    </host></nmaprun>"""
    p = tmp_path / "s.xml"
    p.write_text(xml)
    assert [t.url for t in from_nmap_xml(p)] == ["http://1.2.3.4:5000"]


def test_nmap_falls_back_to_ip_without_hostname(tmp_path):
    xml = """<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
      <address addr="1.2.3.4" addrtype="ipv4"/>
      <ports><port portid="8000"><state state="open"/>
        <service name="http"/></port></ports>
    </host></nmaprun>"""
    p = tmp_path / "s.xml"
    p.write_text(xml)
    assert [t.url for t in from_nmap_xml(p)] == ["http://1.2.3.4:8000"]


def test_nmap_not_xml(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("this is not xml <<<")
    with pytest.raises(InputError, match="not valid XML"):
        from_nmap_xml(p)


def test_nmap_wrong_root(tmp_path):
    p = tmp_path / "wrong.xml"
    p.write_text("<rss><channel/></rss>")
    with pytest.raises(InputError, match="does not look like an Nmap"):
        from_nmap_xml(p)


def test_nmap_no_web_ports(tmp_path):
    xml = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
      <address addr="1.2.3.4" addrtype="ipv4"/>
      <ports><port portid="22"><state state="open"/>
        <service name="ssh"/></port></ports></host></nmaprun>"""
    p = tmp_path / "s.xml"
    p.write_text(xml)
    with pytest.raises(InputError, match="no open web ports"):
        from_nmap_xml(p)


# --- dedupe / collect ------------------------------------------------------


def test_dedupe_preserves_order():
    ts = [Target("http://a"), Target("http://b"), Target("http://a")]
    assert [t.url for t in dedupe(ts)] == ["http://a", "http://b"]


def test_collect_requires_an_input():
    with pytest.raises(InputError, match="no targets given"):
        collect_targets()


def test_collect_merges_and_dedupes(tmp_path):
    p = tmp_path / "u.txt"
    p.write_text("https://example.com\n")
    targets = collect_targets(file=p, single="https://example.com")
    assert len(targets) == 1  # same URL from two sources deduped
