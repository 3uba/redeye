"""A deliberately naive technology fingerprint.

This is a hint, not Wappalyzer. Each label maps to a list of signatures; a
signature is a substring searched (case-insensitively) across a haystack built
from the response headers and the HTML body. Adding a new rule is a one-line
edit to :data:`RULES`.

Labels in :data:`HIGH_INTEREST` float their hosts into the report's "High
interest" section -- known apps and login pages, the things worth looking at
first.
"""

from __future__ import annotations

import re

#: {label: [signatures]} -- a signature is a plain substring (lower-cased
#: before comparison). Keep these short and readable; order doesn't matter.
RULES: dict[str, list[str]] = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-login", "x-pingback"],
    "Drupal": ["x-drupal", "/sites/default/", "drupal.settings", "x-generator: drupal"],
    "Joomla": ["/media/jui/", "joomla", "com_content"],
    "Tomcat": ["apache tomcat", "apache-coyote", "/manager/html"],
    "Jenkins": ["x-jenkins", "jenkins-session", "dashboard.jenkins"],
    "GitLab": ["gitlab", "x-gitlab"],
    "phpMyAdmin": ["phpmyadmin", "pma_", "phpmyadmin.css"],
    "Grafana": ["grafana", "grafana_session"],
    "Kibana": ["kbn-name", "kibana"],
    "Nginx": ["server: nginx"],
    "Apache": ["server: apache"],
    "IIS": ["server: microsoft-iis", "x-aspnet-version", "x-powered-by: asp.net"],
    "PHP": ["x-powered-by: php", ".php"],
    "Express": ["x-powered-by: express"],
    "Spring Boot": ["whitelabel error page", "x-application-context"],
    "Django": ["csrfmiddlewaretoken", "csrftoken", "__admin__", "/static/admin/"],
    "Default/Placeholder page": [
        "it works!",
        "welcome to nginx",
        "apache2 debian default page",
        "iis windows server",
        "test page for the apache",
    ],
}

#: A login form is detected structurally rather than by a vendor string.
_LOGIN_PATTERNS = [
    re.compile(r"<input[^>]+type=['\"]?password['\"]?", re.IGNORECASE),
    re.compile(r"name=['\"]?(username|user|login|email)['\"]?", re.IGNORECASE),
]
LOGIN_LABEL = "Login page"

#: Labels that mark a host as high-interest (surfaced first in the report).
#: Everything that is a named application, plus login pages.
_NON_APP_LABELS = {
    "Nginx",
    "Apache",
    "IIS",
    "PHP",
    "Express",
    "Default/Placeholder page",
}
HIGH_INTEREST: set[str] = (set(RULES) - _NON_APP_LABELS) | {LOGIN_LABEL}


def _build_haystack(headers: dict[str, str], body: str) -> str:
    """Combine headers and body into one lower-cased search string.

    Headers are rendered as ``name: value`` lines so a signature like
    ``server: nginx`` matches a header rather than an incidental body string.
    Each header is emitted twice: once verbatim, and once with the value's
    internal whitespace collapsed to single spaces. The second form keeps a
    rule like ``server: nginx`` matching even when a proxy or framework has
    prepended another token to the value (``Server: foo\\nnginx``), which would
    otherwise break the "value starts right after the colon" assumption.
    """
    lines: list[str] = []
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
        collapsed = " ".join(value.split())
        if collapsed != value:
            lines.append(f"{name}: {collapsed}")
    return ("\n".join(lines) + "\n" + body).lower()



def _looks_like_login(body: str) -> bool:
    """Heuristic: a password input (plus ideally a username-ish field)."""
    has_password = bool(_LOGIN_PATTERNS[0].search(body))
    if not has_password:
        return False
    return True


def fingerprint(headers: dict[str, str], body: str, title: str = "") -> list[str]:
    """Return a sorted list of technology labels detected for a response.

    ``headers`` is a name->value mapping, ``body`` the HTML, ``title`` the page
    title (folded into the body haystack so title-based rules like "Apache
    Tomcat" work). The result is deterministic (sorted) so reports are stable.
    """
    haystack = _build_haystack(headers, f"{title}\n{body}")
    labels: set[str] = set()

    for label, signatures in RULES.items():
        if any(sig.lower() in haystack for sig in signatures):
            labels.add(label)

    if _looks_like_login(body):
        labels.add(LOGIN_LABEL)

    return sorted(labels)


def is_high_interest(labels: list[str]) -> bool:
    """Whether any label marks this host as worth looking at first."""
    return any(label in HIGH_INTEREST for label in labels)
