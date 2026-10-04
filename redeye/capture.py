"""Async capture: visit each target, screenshot it, collect HTTP metadata.

The browser side uses Playwright's native-ARM Chromium (the reason redeye
exists). Headers are also fetched independently with httpx, because the two can
disagree -- a header fetch can time out while the screenshot still renders, or
vice versa -- and a recon tool should record both rather than pick one.

Everything here is failure-tolerant: a dead, slow, or hostile host becomes a
recorded :class:`CaptureResult` with a status like ``"timeout"`` or
``"error"``, never an exception that aborts the run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .fingerprint import fingerprint, is_high_interest
from .inputs import Target


class ChromiumMissingError(RuntimeError):
    """Raised when Playwright's Chromium browser is not installed."""


@dataclass
class CaptureResult:
    """Everything learned about one target. Always serializable."""

    url: str
    final_url: str = ""
    status: int | None = None
    # outcome is a coarse string for the report: "ok", "timeout", "error".
    outcome: str = "ok"
    title: str = ""
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # headers as seen by the independent httpx fetch (may differ from browser)
    http_headers: dict[str, str] = field(default_factory=dict)
    http_status: int | None = None
    tech: list[str] = field(default_factory=list)
    screenshot: str = ""  # relative path within the output dir, or ""
    error: str = ""
    source: str = "file"

    @property
    def high_interest(self) -> bool:
        return is_high_interest(self.tech)

    def to_dict(self) -> dict:
        """A JSON-friendly dict for results.json."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "outcome": self.outcome,
            "title": self.title,
            "server": self.server,
            "headers": self.headers,
            "http_headers": self.http_headers,
            "http_status": self.http_status,
            "tech": self.tech,
            "screenshot": self.screenshot,
            "error": self.error,
            "source": self.source,
            "high_interest": self.high_interest,
        }


@dataclass
class CaptureConfig:
    """Knobs for a capture run."""

    threads: int = 10
    timeout: float = 10.0
    insecure: bool = False
    screens_dir: Path = field(default_factory=lambda: Path("screens"))
    viewport_width: int = 1280
    viewport_height: int = 800
    user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) redeye/0.1 Chrome/120.0 Safari/537.36"
    )


def _safe_filename(url: str, index: int) -> str:
    """A filesystem-safe screenshot name derived from the URL and an index."""
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    slug = "".join(c if c in keep else "_" for c in url)
    slug = slug[:80].strip("_") or "target"
    return f"{index:04d}_{slug}.png"


async def _fetch_headers(
    client: httpx.AsyncClient, url: str
) -> tuple[int | None, dict[str, str], str]:
    """Fetch status + headers with httpx, independently of the browser.

    Returns ``(status, headers, error)``. Never raises; a failure becomes an
    error string and empty headers so the caller can record the disagreement.
    """
    try:
        response = await client.get(url)
        headers = {k: v for k, v in response.headers.items()}
        return response.status_code, headers, ""
    except httpx.TimeoutException:
        return None, {}, "header fetch timed out"
    except httpx.ConnectError as exc:
        return None, {}, f"connect error: {exc}"
    except httpx.HTTPError as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


async def _capture_one(
    target: Target,
    index: int,
    browser,
    client: httpx.AsyncClient,
    config: CaptureConfig,
    on_done=None,
) -> CaptureResult:
    """Visit one target in its own browser context; collect everything."""
    result = CaptureResult(url=target.url, source=target.source)
    timeout_ms = int(config.timeout * 1000)

    # Independent header fetch and the browser visit run concurrently.
    header_task = asyncio.create_task(_fetch_headers(client, target.url))

    context = None
    try:
        context = await browser.new_context(
            ignore_https_errors=config.insecure,
            user_agent=config.user_agent,
            viewport={
                "width": config.viewport_width,
                "height": config.viewport_height,
            },
        )
        page = await context.new_page()
        page.set_default_timeout(timeout_ms)

        response = await page.goto(
            target.url, timeout=timeout_ms, wait_until="domcontentloaded"
        )

        result.final_url = page.url
        if response is not None:
            result.status = response.status
            result.headers = {k: v for k, v in response.headers.items()}
            result.server = result.headers.get("server", "")

        try:
            result.title = (await page.title()) or ""
        except Exception:  # noqa: BLE001 - title is best-effort
            result.title = ""

        body = ""
        try:
            body = await page.content()
        except Exception:  # noqa: BLE001
            body = ""

        screenshot_name = _safe_filename(target.url, index)
        screenshot_path = config.screens_dir / screenshot_name
        try:
            await page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot = f"{config.screens_dir.name}/{screenshot_name}"
        except Exception as exc:  # noqa: BLE001 - some pages refuse full_page
            try:
                await page.screenshot(path=str(screenshot_path), full_page=False)
                result.screenshot = f"{config.screens_dir.name}/{screenshot_name}"
            except Exception:  # noqa: BLE001
                result.error = f"screenshot failed: {exc}"

        result.tech = fingerprint(result.headers, body, result.title)
        result.outcome = "ok"

    except PlaywrightTimeout:
        result.outcome = "timeout"
        result.error = f"navigation timed out after {config.timeout:g}s"
    except Exception as exc:  # noqa: BLE001 - any nav failure is a recorded outcome
        result.outcome = "error"
        result.error = _explain_browser_error(exc)
    finally:
        if context is not None:
            try:
                await context.close()
            except Exception:  # noqa: BLE001
                pass

    # Fold in the independent header fetch.
    http_status, http_headers, http_error = await header_task
    result.http_status = http_status
    result.http_headers = http_headers
    if not result.headers and http_headers:
        # Browser gave us nothing but httpx did -- use its view for tech/server.
        result.headers = http_headers
        result.server = http_headers.get("server", "")
        if not result.tech:
            result.tech = fingerprint(http_headers, "", result.title)
    if http_error and result.outcome == "ok":
        result.error = (result.error + "; " if result.error else "") + http_error

    if on_done is not None:
        on_done(result)
    return result


def _explain_browser_error(exc: Exception) -> str:
    """Turn a Playwright navigation exception into a readable line."""
    text = str(exc)
    lowered = text.lower()
    if "net::err_connection_refused" in lowered:
        return "connection refused"
    if "net::err_name_not_resolved" in lowered:
        return "DNS resolution failed"
    if "net::err_cert" in lowered or "ssl" in lowered:
        return "TLS certificate error (try --insecure)"
    if "net::err_connection_timed_out" in lowered:
        return "connection timed out"
    if "net::err_connection_reset" in lowered:
        return "connection reset"
    # Trim Playwright's verbose multi-line messages to the first line.
    return text.splitlines()[0] if text else type(exc).__name__


# Playwright is imported lazily so that `redeye --help`, the tests, and the
# input parsing all work without Playwright installed. The real import happens
# inside run_captures().
PlaywrightTimeout: type[Exception] = asyncio.TimeoutError  # replaced at runtime


async def run_captures(
    targets: list[Target],
    config: CaptureConfig,
    on_done=None,
) -> list[CaptureResult]:
    """Capture every target concurrently and return results in input order.

    A worker pool of ``config.threads`` visits run at once; one slow host never
    blocks the others. ``on_done`` (optional) is called with each result as it
    finishes, for progress display.

    Raises :class:`ChromiumMissingError` if Chromium is not installed -- the CLI
    turns that into the exact install command rather than a traceback.
    """
    global PlaywrightTimeout
    try:
        from playwright.async_api import async_playwright
        from playwright.async_api import Error as PWError
        from playwright.async_api import TimeoutError as PWTimeout
    except ImportError:
        raise ChromiumMissingError(
            "Playwright is not installed. Install redeye's dependencies, then "
            "run:\n    playwright install chromium"
        ) from None

    PlaywrightTimeout = PWTimeout

    config.screens_dir.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(max(1, config.threads))
    results: list[CaptureResult | None] = [None] * len(targets)

    verify = not config.insecure
    http_limits = httpx.Limits(max_connections=config.threads * 2)

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True)
        except PWError as exc:
            message = str(exc).lower()
            if "executable doesn't exist" in message or "looks like" in message:
                raise ChromiumMissingError(
                    "Playwright's Chromium browser is not installed. Run:\n"
                    "    playwright install chromium"
                ) from None
            raise ChromiumMissingError(
                f"could not launch Chromium: {str(exc).splitlines()[0]}"
            ) from None

        async with httpx.AsyncClient(
            verify=verify,
            timeout=config.timeout,
            follow_redirects=True,
            limits=http_limits,
            headers={"User-Agent": config.user_agent},
        ) as client:

            async def worker(target: Target, index: int) -> None:
                async with semaphore:
                    results[index] = await _capture_one(
                        target, index, browser, client, config, on_done
                    )

            await asyncio.gather(
                *(worker(t, i) for i, t in enumerate(targets)),
                return_exceptions=False,
            )

        await browser.close()

    # Fill any gaps defensively (shouldn't happen, but never return None).
    return [
        r if r is not None else CaptureResult(url=targets[i].url, outcome="error",
                                              error="no result produced")
        for i, r in enumerate(results)
    ]
