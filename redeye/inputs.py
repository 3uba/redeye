"""Turn the various input sources into a normalized list of :class:`Target`s.

Three sources feed in -- a line-separated URL/host file, an Nmap XML scan, and
a single ``--single`` target -- and all three produce the same thing: a list of
``Target`` objects with a concrete URL to visit. Everything downstream
(capture, report) sees only ``Target``s and never has to care where they came
from.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

#: Ports we treat as web-ish even when Nmap's service name doesn't say "http".
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}

#: Ports that imply TLS when we have nothing else to go on.
TLS_PORTS = {443, 8443}


class InputError(ValueError):
    """Raised for unreadable files, malformed XML, or empty input."""


@dataclass
class Target:
    """A single thing to visit.

    ``url`` is always concrete and schemed. ``source`` records where it came
    from (``file`` / ``nmap`` / ``single``) purely for debugging and the report.
    ``needs_probe`` marks a bare host whose scheme we guessed and may need to
    fall back on (https -> http) at capture time.
    """

    url: str
    source: str = "file"
    needs_probe: bool = False

    def __hash__(self) -> int:  # dedupe by URL
        return hash(self.url)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Target) and other.url == self.url


def _has_scheme(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def normalize_host_entry(
    entry: str, default_scheme: str = "auto"
) -> Target | None:
    """Normalize one line (a URL or ``host[:port][/path]``) into a Target.

    Returns ``None`` for blank lines and comments. ``default_scheme`` is one of
    ``http``, ``https``, or ``auto`` (probe https then http).
    """
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None

    if _has_scheme(entry):
        return Target(url=entry, source="file")

    # Bare host[:port][/path]. Decide a scheme.
    host_part = entry.split("/", 1)[0]
    port: int | None = None
    if ":" in host_part and not host_part.startswith("["):
        _, _, port_str = host_part.rpartition(":")
        if port_str.isdigit():
            port = int(port_str)

    if default_scheme in ("http", "https"):
        return Target(url=f"{default_scheme}://{entry}", source="file")

    # auto: a TLS-looking port forces https; otherwise guess https and allow a
    # fallback probe to http at capture time.
    if port in TLS_PORTS:
        return Target(url=f"https://{entry}", source="file")
    if port is not None and port not in TLS_PORTS:
        return Target(url=f"http://{entry}", source="file")
    return Target(url=f"https://{entry}", source="file", needs_probe=True)


def from_file(path: Path, default_scheme: str = "auto") -> list[Target]:
    """Read a line-separated URL/host file into Targets."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise InputError(f"no such file: {path}") from None
    except IsADirectoryError:
        raise InputError(f"{path} is a directory, not a file") from None
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from None

    targets: list[Target] = []
    for line in text.splitlines():
        target = normalize_host_entry(line, default_scheme)
        if target is not None:
            targets.append(target)
    if not targets:
        raise InputError(f"{path} contained no usable targets")
    return targets


def from_single(value: str, default_scheme: str = "auto") -> list[Target]:
    """Normalize a single ``--single`` target."""
    target = normalize_host_entry(value, default_scheme)
    if target is None:
        raise InputError(f"{value!r} is not a usable target")
    target.source = "single"
    return [target]


def _port_is_web(port: int, service_name: str) -> bool:
    """Decide whether an Nmap port is worth visiting over HTTP."""
    if port in WEB_PORTS:
        return True
    return "http" in service_name.lower()


def _port_is_tls(port: int, service_name: str, tunnel: str) -> bool:
    """Decide whether to use https for an Nmap port."""
    if tunnel.lower() == "ssl":
        return True
    if port in TLS_PORTS:
        return True
    name = service_name.lower()
    return "https" in name or "ssl" in name or "tls" in name


def from_nmap_xml(path: Path) -> list[Target]:
    """Parse an Nmap XML file into Targets for every open web-ish port.

    Hosts are addressed by hostname when the XML carries one, else by IP.
    http:// is used for plain ports, https:// for ssl/tls ports.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise InputError(f"no such file: {path}") from None
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from None

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise InputError(f"{path} is not valid XML: {exc}") from None

    if root.tag != "nmaprun":
        raise InputError(
            f"{path} does not look like an Nmap XML file (root tag is "
            f"{root.tag!r}, expected 'nmaprun')"
        )

    targets: list[Target] = []
    for host in root.findall("host"):
        # Skip hosts Nmap marked as down.
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue

        address = _host_address(host)
        if address is None:
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port_el in ports.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_el.get("portid", ""))
            except ValueError:
                continue

            service = port_el.find("service")
            service_name = service.get("name", "") if service is not None else ""
            tunnel = service.get("tunnel", "") if service is not None else ""

            if not _port_is_web(port, service_name):
                continue

            scheme = "https" if _port_is_tls(port, service_name, tunnel) else "http"
            # Omit the port when it's the scheme default, for tidy URLs.
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                url = f"{scheme}://{address}"
            else:
                url = f"{scheme}://{address}:{port}"
            targets.append(Target(url=url, source="nmap"))

    if not targets:
        raise InputError(f"{path} had no open web ports to visit")
    return targets


def _host_address(host: ET.Element) -> str | None:
    """Prefer a hostname from the XML, fall back to the IP address."""
    hostnames = host.find("hostnames")
    if hostnames is not None:
        for hostname in hostnames.findall("hostname"):
            name = hostname.get("name")
            if name:
                return name
    for addr in host.findall("address"):
        addrtype = addr.get("addrtype", "")
        if addrtype in ("ipv4", "ipv6"):
            ip = addr.get("addr")
            if ip:
                return f"[{ip}]" if addrtype == "ipv6" else ip
    return None


def dedupe(targets: list[Target]) -> list[Target]:
    """Remove duplicate URLs while preserving first-seen order."""
    seen: set[str] = set()
    out: list[Target] = []
    for target in targets:
        if target.url not in seen:
            seen.add(target.url)
            out.append(target)
    return out


def collect_targets(
    *,
    file: Path | None = None,
    nmap_xml: Path | None = None,
    single: str | None = None,
    default_scheme: str = "auto",
) -> list[Target]:
    """Gather every input source into one deduped Target list."""
    targets: list[Target] = []
    if file is not None:
        targets.extend(from_file(file, default_scheme))
    if nmap_xml is not None:
        targets.extend(from_nmap_xml(nmap_xml))
    if single is not None:
        targets.extend(from_single(single, default_scheme))

    if not targets:
        raise InputError("no targets given (use -f, -x, or --single)")
    return dedupe(targets)
