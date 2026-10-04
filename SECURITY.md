# Security Policy

## Responsible use

`redeye` is a reconnaissance tool: it visits web targets, screenshots them, and
collects HTTP metadata. Use it **only against systems you own or are explicitly
authorized to test** — your own lab, a deliberately vulnerable box (Hack The
Box, TryHackMe, and similar), or an engagement or bug-bounty program whose scope
covers the target in writing.

Pointing redeye at hosts you do not have permission to assess may be illegal in
your jurisdiction. You are solely responsible for how you use this tool.

## Reporting a vulnerability

If you find a security issue **in redeye itself** (for example, a way a malicious
page's content could compromise the machine running redeye, or be injected into
the generated HTML report), please report it privately rather than opening a
public issue:

- Open a [GitHub Security Advisory](https://github.com/3uba/redeye/security/advisories/new), or
- Open a regular issue that says only "security report — please contact me" with
  no details, and we will arrange a private channel.

Please do not disclose the issue publicly until a fix is available. I aim to
acknowledge reports within a few days.

## Scope

In scope: bugs in redeye's own code (input parsing, capture, the generated
report) that affect the security of the user running it. Note that redeye's HTML
report escapes untrusted content (page titles, headers) via Jinja2 autoescaping;
a bypass of that escaping is in scope.

Out of scope: vulnerabilities you discover in *third-party* targets using redeye —
report those to the affected vendor or through the relevant bug-bounty program,
not here.
