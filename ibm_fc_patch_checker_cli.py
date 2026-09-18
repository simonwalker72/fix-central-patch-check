#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IBM Fix Central Patch Checker
==============================
Lists available fixes for any IBM product on Fix Central, grouped by category
and sorted by release date (newest first).

Usage
-----
  python ibm_fc_patch_checker_cli.py websphere
  python ibm_fc_patch_checker_cli.py db2
  python ibm_fc_patch_checker_cli.py guardium --releases 12.2 12.x
  python ibm_fc_patch_checker_cli.py guardium --platforms Linux
  python ibm_fc_patch_checker_cli.py guardium --newest-only
  python ibm_fc_patch_checker_cli.py guardium --output fixes.csv
  python ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux
  python ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux --category "KTAP Bundle"
  python ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux --category "Database Agent (STAP, GIM and CAS)"
  python ibm_fc_patch_checker_cli.py "WebSphere Application Server" --releases 9.0.5.29 --platforms "Windows 64-bit, x86"

Requirements
------------
  pip install playwright rich
  playwright install chromium
"""

import argparse
import csv
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.prompt import Prompt

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

console        = Console(highlight=False)
console_stderr = Console(highlight=False, stderr=True)


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

_LEVEL_STYLES = {
    "INFO": "color(67)",   # muted grey-blue (steel blue), matching CVE CLI style
    "OK":   "green",
    "WARN": "yellow",
    "ERR":  "bold red",
}

def _log(level: str, msg: str, *, end: str = "\n", file=None) -> None:
    """Print a rich-styled timestamped log line: [HH:MM:SS] [LEVEL] msg"""
    ts    = datetime.now().strftime("%H:%M:%S")
    style = _LEVEL_STYLES.get(level, "white")
    line  = f"[dim][{ts}][/dim] [[{style}]{level}[/{style}]] {msg}"
    if file is sys.stderr:
        console_stderr.print(line, end=end, highlight=False)
    else:
        console.print(line, end=end, highlight=False)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FC_TRUSTED_HOST     = "www.ibm.com"
_FC_FIND_URL         = "https://www.ibm.com/support/fixcentral/find?text={query}"
_FC_VERSIONS_BASE    = "https://www.ibm.com/support/fixcentral/options?selectionBean.selectedTab=find&selection={selection}"
_FC_SELECT_FIXES_URL = (
    "https://www.ibm.com/support/fixcentral/swg/selectFixes"
    "?parent={parent}"
    "&product={product}"
    "&release={release}"
    "&platform={platform}"
    "&function=all"
)

_MAX_FIX_ID_LEN = 200


def _script_name() -> str:
    """Return just the script filename for use in tip messages."""
    return os.path.basename(sys.argv[0])


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != _FC_TRUSTED_HOST:
        raise ValueError(
            f"Refusing to load untrusted URL: {url!r}  "
            f"(expected https://{_FC_TRUSTED_HOST}/...)"
        )


def _sanitise_fix_id(raw: str) -> str:
    value = raw.strip()
    # Must start with a word character and contain only word chars, dots, hyphens.
    if not re.fullmatch(r'\w[\w.\-]*', value):
        raise ValueError(f"Unexpected characters in fix_id: {value!r}")
    return value[:_MAX_FIX_ID_LEN]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FixEntry:
    release:      str
    category:     str
    fix_id:       str
    release_date: str
    platform:     str
    date_obj:     Optional[datetime] = field(default=None, repr=False)

    def __post_init__(self):
        normalised = self.release_date.replace("-", "/")
        self.release_date = normalised
        try:
            self.date_obj = datetime.strptime(normalised.replace("/", "-"), "%Y-%m-%d")
        except ValueError:
            self.date_obj = None


@dataclass
class ProductMatch:
    display_name: str
    selection:    str
    parent:       str
    product:      str


def _sort_key(
    e: FixEntry,
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> tuple:
    # Always use int ranks so the tuple element types are consistent regardless
    # of whether order dicts are supplied.  Fall back to 0 so unseen values
    # sort to the front rather than hiding behind a magic sentinel.
    rel_rank  = release_order.get(e.release,   0) if release_order  else 0
    plat_rank = platform_order.get(e.platform, 0) if platform_order else 0
    return (
        rel_rank,
        plat_rank,
        e.category,
        -(e.date_obj.timestamp() if e.date_obj else 0),
    )


# ---------------------------------------------------------------------------
# Product search  (plain HTTP — no Playwright needed)
# ---------------------------------------------------------------------------

def search_products(query: str, timeout: int = 15) -> list[ProductMatch]:
    """Query Fix Central's product-search endpoint and return matching products."""
    url = _FC_FIND_URL.format(query=urllib.parse.quote(query))
    _validate_url(url)

    req = urllib.request.Request(url, headers={
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except OSError as exc:
        _log("WARN", f"Product search request failed: {exc}", file=sys.stderr)
        return []

    seen_names: set[str] = set()
    products: list[ProductMatch] = []
    for m in re.finditer(
        r'<a\s+href="[^"]*selection=([^"&]+)"[^>]*>(.*?)</a>',
        html, re.DOTALL
    ):
        raw_selection = urllib.parse.unquote_plus(m.group(1))
        display = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        if not display:
            continue
        # Skip duplicates (Fix Central sometimes returns the same product twice)
        if display.lower() in seen_names:
            continue
        seen_names.add(display.lower())

        if ";" in raw_selection:
            parent_raw, product_raw = raw_selection.split(";", 1)
        else:
            parent_raw = raw_selection
            product_raw = raw_selection

        # Fix Central URL encoding rules (observed from browser):
        #   parent:  "/" → "~",  spaces → "~"
        #     e.g. "ibm/WebSphere" → "ibm~WebSphere"
        #   product: "/" preserved, spaces → "+"
        #     e.g. "ibm/WebSphere/WebSphere Application Server"
        #          → "ibm/WebSphere/WebSphere+Application+Server"
        parent  = parent_raw.replace("/", "~").replace(" ", "~")
        product = urllib.parse.quote(product_raw, safe="/").replace("%20", "+")
        selection_encoded = urllib.parse.quote(raw_selection, safe="")

        products.append(ProductMatch(
            display_name=display,
            selection=selection_encoded,
            parent=parent,
            product=product,
        ))

    return sorted(products, key=lambda p: p.display_name.lower())


# ---------------------------------------------------------------------------
# Product selection prompt
# ---------------------------------------------------------------------------

def prompt_product_choice(products: list[ProductMatch], query: str) -> Optional[ProductMatch]:
    """Present matching products as a rich table and return the chosen one."""
    if not products:
        _log("WARN", f"No products found matching '{query}'.", file=sys.stderr)
        return None

    console.print()
    console.print(Rule(f"[bold cyan]Products matching '[yellow]{query}[/yellow]'[/bold cyan]",
                       style="cyan"))
    console.print()

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                show_edge=False, pad_edge=True)
    tbl.add_column("#",    style="dim", width=4, justify="right")
    tbl.add_column("Product Name", style="white")

    for i, p in enumerate(products, 1):
        tbl.add_row(str(i), p.display_name)

    console.print(tbl)

    if len(products) == 1:
        _log("INFO", f"Auto-selecting: [bold]{products[0].display_name}[/bold]")
        return products[0]

    while True:
        try:
            raw = Prompt.ask("  [cyan]Select product number[/cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None
        if not raw:
            continue
        try:
            idx = int(raw)
            if 1 <= idx <= len(products):
                return products[idx - 1]
            _log("WARN", f"Please enter a number between 1 and {len(products)}.")
        except ValueError:
            _log("WARN", "Please enter a number.")


# ---------------------------------------------------------------------------
# Release version discovery
# ---------------------------------------------------------------------------

def _parse_releases_from_html(html: str) -> list[str]:
    first_select = re.search(
        r'<select[^>]*name=["\']release["\'][^>]*>(.*?)</select>',
        html, re.DOTALL
    )
    if not first_select:
        first_select = re.search(
            r'<select[^>]*id=["\']selectRelease["\'][^>]*>(.*?)</select>',
            html, re.DOTALL
        )
    if not first_select:
        return []
    versions = re.findall(r'<option[^>]+value="([^"]+)"', first_select.group(1))
    raw = [v for v in versions if v not in ("-1", "All")]
    return sorted(raw, key=_version_sort_key, reverse=True)


def _version_sort_key(v: str) -> tuple:
    """
    Sort key that orders version strings numerically, newest first.
    e.g. "12.2" > "12.1" > "11.5" > "9.8.*" > "8.*"
    Non-numeric tokens (like "fp0", "*") sort after numeric ones.
    """
    parts = re.split(r'[.\-]', v.replace("*", "0"))
    result = []
    for p in parts:
        # strip non-digit suffixes like "fp0" -> try leading digits
        m = re.match(r'^(\d+)', p)
        result.append(int(m.group(1)) if m else -1)
    return tuple(result)


def _build_versions_url(product: ProductMatch) -> str:
    return _FC_VERSIONS_BASE.format(selection=product.selection)


def prompt_release_choice(releases: list[str]) -> list[str]:
    """Present discovered releases as a rich table and let the user pick."""
    console.print()
    console.print(Rule("[bold cyan]Available Releases[/bold cyan]", style="cyan"))
    console.print()

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                show_edge=False, pad_edge=True)
    tbl.add_column("#",       style="dim", width=4, justify="right")
    tbl.add_column("Version", style="white")

    for i, r in enumerate(releases, 1):
        tbl.add_row(str(i), r)

    console.print(tbl)
    console.print("  Enter number(s) separated by spaces, or press [bold]Enter[/bold] to include all:")

    while True:
        try:
            raw = Prompt.ask("  [cyan]>[/cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return releases

        if not raw:
            return releases

        chosen = []
        valid  = True
        for token in raw.split():
            try:
                idx = int(token)
                if 1 <= idx <= len(releases):
                    chosen.append(releases[idx - 1])
                else:
                    _log("WARN", f"'{token}' is out of range (1–{len(releases)}) — try again.")
                    valid = False
                    break
            except ValueError:
                _log("WARN", f"'{token}' is not a number — try again.")
                valid = False
                break

        if valid and chosen:
            return chosen


def _parse_platforms_from_html(html: str) -> list[str]:
    """Extract platform strings from the Fix Central product-page HTML."""
    m = re.search(
        r'<select[^>]*name=["\']platform["\'][^>]*>(.*?)</select>',
        html, re.DOTALL
    )
    if not m:
        return []
    opts = re.findall(r'<option[^>]+value="([^"]+)"', m.group(1))
    return [v for v in opts if v not in ("-1", "All")]


def prompt_platform_choice(platforms: list[str]) -> list[str]:
    """Present discovered platforms as a rich table and let the user pick."""
    console.print()
    console.print(Rule("[bold cyan]Available Platforms[/bold cyan]", style="cyan"))
    console.print()

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                show_edge=False, pad_edge=True)
    tbl.add_column("#",        style="dim", width=4, justify="right")
    tbl.add_column("Platform", style="white")

    for i, p in enumerate(platforms, 1):
        tbl.add_row(str(i), p)

    console.print(tbl)
    console.print("  Enter number(s) separated by spaces, or press [bold]Enter[/bold] to include all:")

    while True:
        try:
            raw = Prompt.ask("  [cyan]>[/cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return platforms

        if not raw:
            return platforms

        chosen = []
        valid  = True
        for token in raw.split():
            try:
                idx = int(token)
                if 1 <= idx <= len(platforms):
                    chosen.append(platforms[idx - 1])
                else:
                    _log("WARN", f"'{token}' is out of range (1–{len(platforms)}) — try again.")
                    valid = False
                    break
            except ValueError:
                _log("WARN", f"'{token}' is not a number — try again.")
                valid = False
                break

        if valid and chosen:
            return chosen


def _fetch_releases_and_platforms_with_page(
    page, versions_url: str, page_timeout: int
) -> tuple[list[str], list[str]]:
    """
    Navigate to the product's versions URL, extract the release dropdown,
    then select the first release to trigger platform population and extract
    the platform dropdown too.

    Returns (releases, platforms).  Either list may be empty on failure.
    """
    from playwright.sync_api import TimeoutError as PWTimeout  # type: ignore[import-untyped]

    _validate_url(versions_url)
    _log("INFO", "Loading release and platform lists ...")
    t0 = time.monotonic()
    try:
        page.goto(versions_url, wait_until="domcontentloaded",
                  timeout=page_timeout * 1000)
        # Wait for release dropdown (hidden by select2 → use state="attached")
        page.wait_for_selector(
            "select[name='release'] option:not([value='-1']):not([value='All'])",
            state="attached",
            timeout=page_timeout * 1000,
        )
        releases = _parse_releases_from_html(page.content())

        # Select the first release so the platform dropdown is populated by JS
        if releases:
            page.evaluate(
                f"document.querySelector(\"select[name='release']\").value = {releases[0]!r}"
            )
            page.dispatch_event("select[name='release']", "change")
            # Wait for platform to populate
            page.wait_for_selector(
                "select[name='platform'] option:not([value='-1']):not([value='All'])",
                state="attached",
                timeout=page_timeout * 1000,
            )
        platforms = _parse_platforms_from_html(page.content())
    except (PWTimeout, OSError) as exc:
        _log("WARN", f"Could not load version/platform lists: {exc}", file=sys.stderr)
        return [], []

    elapsed = time.monotonic() - t0
    if not releases:
        _log("WARN", "Release dropdown found but no versions could be parsed.",
             file=sys.stderr)
        return [], []

    _log("OK", f"Found [bold]{len(releases)}[/bold] release(s) and "
         f"[bold]{len(platforms)}[/bold] platform(s) in {elapsed:.1f}s")
    return releases, platforms


# ---------------------------------------------------------------------------
# Fix Central page parsing
# ---------------------------------------------------------------------------

def _parse_fc_date(raw: str) -> Optional[str]:
    raw = raw.strip()
    m = re.fullmatch(
        r'\w{3}\s+(\w{3})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+\w+\s+(\d{4})',
        raw,
    )
    if m:
        try:
            dt = datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", "%b %d %Y")
            return dt.strftime("%Y/%m/%d")
        except ValueError:
            pass
    m2 = re.fullmatch(r'(\d{2})/(\d{2})/(\d{4})', raw)
    if m2:
        return f"{m2.group(3)}/{m2.group(1)}/{m2.group(2)}"
    return None


def _wait_for_fixes_loaded(page, timeout_ms: int = 60_000) -> None:
    """Wait until Fix Central has rendered fix results or a no-results message."""
    page.wait_for_function(
        """() => {
            const body = document.body ? (document.body.innerText || '') : '';
            const inputs = document.querySelectorAll('input[type="checkbox"]');
            return (
                body.includes('fix pack') ||
                body.includes('Fix pack') ||
                body.includes('No results were found') ||
                body.includes('no fixes were found') ||
                body.includes('Release date') ||
                inputs.length > 1
            );
        }""",
        timeout=timeout_ms,
    )


_FC_IGNORED_HEADINGS = frozenset({
    "need support?", "about ibm", "ibm research", "industry",
    "partners", "engage with ibm", "select a country/region",
})


def _parse_fix_rows(rows: list[str], category: str,
                    release: str, platform: str) -> list[FixEntry]:
    """Parse a list of <tr> HTML strings into FixEntry objects."""
    entries: list[FixEntry] = []
    for row in rows:
        # Fix ID: any checkbox input whose value looks like a fix identifier
        # (alphanumeric start, may contain dots/hyphens/underscores)
        fix_id_m = re.search(
            r'<input[^>]+type=["\']checkbox["\'][^>]+value="([A-Za-z0-9][^"]{1,190})"'
            r'|'
            r'<input[^>]+value="([A-Za-z0-9][^"]{1,190})"[^>]+type=["\']checkbox["\']',
            row, re.IGNORECASE,
        )
        if not fix_id_m:
            continue
        raw_id = fix_id_m.group(1) or fix_id_m.group(2)
        try:
            fix_id = _sanitise_fix_id(raw_id)
        except ValueError:
            continue

        date_str: Optional[str] = None
        for td in reversed(re.findall(r'<td[^>]*>\s*([^<]{10,200}?)\s*</td>', row)):
            date_str = _parse_fc_date(td.strip())
            if date_str:
                break
        if not date_str:
            continue

        entries.append(FixEntry(
            release=release,
            category=category,
            fix_id=fix_id,
            release_date=date_str,
            platform=platform,
        ))
    return entries


def _parse_fc_page(html: str, release: str, platform: str) -> list[FixEntry]:
    """
    Parse the rendered Fix Central HTML into FixEntry objects.

    Two page layouts are handled:
    - Categorised (e.g. Guardium): fix rows sit inside <h3>-delimited sections.
    - Flat (e.g. WAS): fix rows are in a single table with no <h3> grouping.
    """
    # ── Categorised layout: split on <h3> headings ──────────────────────────
    sections = re.split(r'<h3[^>]*>', html)[1:]
    categorised_entries: list[FixEntry] = []
    for section in sections:
        h3_end = section.find("</h3>")
        if h3_end == -1:
            continue
        heading = re.sub(r'<[^>]+>', '', section[:h3_end]).strip()
        if heading.lower() in _FC_IGNORED_HEADINGS:
            continue
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', section, re.DOTALL)
        categorised_entries.extend(
            _parse_fix_rows(rows, heading, release, platform)
        )

    if categorised_entries:
        return categorised_entries

    # ── Flat layout fallback: scan all <tr> rows in the page ────────────────
    # Use "Fixes" as the category since the page has no grouping headings.
    all_rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
    entries = _parse_fix_rows(all_rows, "Fixes", release, platform)
    return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _quote_if_needed(v: str) -> str:
    """Quote a value with spaces so it is safe to paste back into a shell command."""
    return f'"{v}"' if " " in v else v


def _rejoin_multiword_tokens(tokens: list[str], known: list[str]) -> list[str]:
    """Greedily re-join tokens that were split by the shell into multi-word values.

    e.g. tokens=["IBM", "i", "Windows"] with known=["IBM i", "Windows"]
         → ["IBM i", "Windows"]

    Unrecognised tokens are passed through unchanged so the later validation
    step can report them.
    """
    known_lower = {v.lower(): v for v in known}
    result: list[str] = []
    i = 0
    while i < len(tokens):
        # Try longest possible match first (greedy)
        matched = False
        for length in range(len(tokens) - i, 0, -1):
            candidate = " ".join(tokens[i:i + length])
            if candidate.lower() in known_lower:
                result.append(known_lower[candidate.lower()])
                i += length
                matched = True
                break
        if not matched:
            result.append(tokens[i])
            i += 1
    return result


# ---------------------------------------------------------------------------
# Main scraping orchestrator
# ---------------------------------------------------------------------------

def fetch_fix_central(
    product: ProductMatch,
    releases: list[str],
    platforms: list[str],
    categories: Optional[list[str]] = None,
    page_timeout: int = 90,
    headless: bool = True,  # non-headless mode is not supported; kept for testing only
    discover_releases: bool = False,
    discover_platforms: bool = False,
) -> tuple[list[FixEntry], list[str], list[str]]:
    """Scrape Fix Central for each release × platform combination.

    Returns (entries, releases_used, platforms_used).
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout  # type: ignore[import-untyped]

    all_entries: list[FixEntry] = []
    versions_url = _build_versions_url(product)
    select_fixes_url_template = _FC_SELECT_FIXES_URL.format(
        parent=product.parent,
        product=product.product,
        release="{release}",
        platform="{platform}",
    )

    _log("INFO", "Starting browser ...")
    t_start = time.monotonic()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        _log("OK", f"Browser ready ([dim]{time.monotonic() - t_start:.1f}s[/dim])")
        try:
            ctx = browser.new_context(user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ))
            page = ctx.new_page()

            # Discovery: both releases and platforms come from the same page visit.
            # Always fetch the valid lists so we can validate user-supplied values
            # even when the caller already has releases/platforms from a previous run.
            disc_releases, disc_platforms = _fetch_releases_and_platforms_with_page(
                page, versions_url, page_timeout
            )
            if not disc_releases:
                _log("WARN",
                     "Could not load the Fix Central product page — "
                     "check your network connection or increase [bold]--page-timeout[/bold].",
                     file=sys.stderr)
                return [], [], []

            if discover_releases:
                releases = prompt_release_choice(disc_releases)
                console.print()
            else:
                # Re-join any multi-word release names split by the shell, then validate.
                releases = _rejoin_multiword_tokens(releases, disc_releases)
                valid_releases = [r for r in releases if r in disc_releases]
                invalid = [r for r in releases if r not in disc_releases]
                if invalid:
                    _log("WARN",
                         f"Unknown release(s): [yellow]{', '.join(invalid)}[/yellow]. "
                         f"Valid releases: [dim]{', '.join(disc_releases)}[/dim]",
                         file=sys.stderr)
                if not valid_releases:
                    _log("WARN", "No valid releases to fetch — cannot continue.", file=sys.stderr)
                    return [], [], []
                releases = valid_releases

            if discover_platforms:
                if not disc_platforms:
                    _log("WARN",
                         "Platform discovery returned no results — "
                         "use [bold]--platforms[/bold] to specify explicitly.",
                         file=sys.stderr)
                    return [], [], []
                platforms = prompt_platform_choice(disc_platforms)
                console.print()
            else:
                # Re-join any multi-word platform names split by the shell
                # (e.g. ["IBM", "i"] → ["IBM i"]) before validating.
                platforms = _rejoin_multiword_tokens(platforms, disc_platforms)
                valid_platforms = [p for p in platforms if p in disc_platforms]
                invalid = [p for p in platforms if p not in disc_platforms]
                if invalid:
                    _log("WARN",
                         f"Unknown platform(s): [cyan]{', '.join(invalid)}[/cyan]. "
                         f"Valid platforms: [dim]{', '.join(disc_platforms)}[/dim]",
                         file=sys.stderr)
                if not valid_platforms:
                    _log("WARN", "No valid platforms to fetch — cannot continue.", file=sys.stderr)
                    return [], [], []
                platforms = valid_platforms

            if discover_releases or discover_platforms:
                # Combined copy-pasteable tip covering everything chosen via prompts.
                releases_str  = " ".join(_quote_if_needed(r) for r in releases)
                platforms_str = " ".join(_quote_if_needed(p) for p in platforms)
                _log("INFO",
                     f"Tip: next time run [bold cyan]python {_script_name()} "
                     f'"{product.display_name}"'
                     + f" --releases {releases_str}"
                     + f" --platforms {platforms_str}"
                     + "[/bold cyan] to skip all prompts.")

            combos = list(dict.fromkeys((r, p) for r in releases for p in platforms))
            n = len(combos)
            console.print()
            console.print(Rule(
                f"[bold cyan]Fetching [yellow]{n}[/yellow] combination(s): "
                f"[white]{', '.join(releases)}[/white]  |  "
                f"[white]{', '.join(platforms)}[/white][/bold cyan]",
                style="cyan",
            ))
            console.print()

            for idx, (release, platform) in enumerate(combos, 1):
                url = select_fixes_url_template.format(
                    release=urllib.parse.quote(release),
                    platform=urllib.parse.quote(platform),
                )
                _validate_url(url)

                _log("INFO",
                     f"[[dim]{idx}/{n}[/dim]] [yellow]{release}[/yellow] / [cyan]{platform}[/cyan] ...",
                     end="  ")
                t0 = time.monotonic()
                try:
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=page_timeout * 1000)
                    _wait_for_fixes_loaded(page, timeout_ms=page_timeout * 1000)
                except PWTimeout:
                    console.print(f"[red]TIMED OUT[/red] ([dim]{time.monotonic()-t0:.0f}s[/dim])")
                    _log("WARN", f"Timed out for {release}/{platform}", file=sys.stderr)
                    continue
                except OSError as exc:
                    console.print("[red]ERROR[/red]")
                    _log("WARN", f"Network error for {release}/{platform}: {exc}", file=sys.stderr)
                    continue

                entries = _parse_fc_page(page.content(), release, platform)
                if categories:
                    entries = [e for e in entries if e.category in categories]

                elapsed = time.monotonic() - t0
                console.print(
                    f"[green]{len(entries)} fixes[/green]  "
                    f"[dim]({elapsed:.1f}s)[/dim]"
                )
                all_entries.extend(entries)

        finally:
            browser.close()

    return all_entries, releases, platforms


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

DEFAULT_LIMIT = 10


def _print_table(
    entries: list[FixEntry],
    limit: Optional[int] = DEFAULT_LIMIT,
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> None:
    """Print fixes grouped by release/platform → category using rich tables."""
    sorted_entries = sorted(entries, key=lambda e: _sort_key(e, release_order, platform_order))

    totals: dict[tuple, int] = {}
    for e in sorted_entries:
        k = (e.release, e.platform, e.category)
        totals[k] = totals.get(k, 0) + 1

    current_release  = None
    current_platform = None
    current_category = None
    current_tbl: Optional[Table] = None
    category_count   = 0

    def _flush_table():
        if current_tbl is not None:
            console.print(current_tbl)

    for e in sorted_entries:
        # New release/platform group
        if e.release != current_release or e.platform != current_platform:
            _flush_table()
            current_tbl = None
            current_release  = e.release
            current_platform = e.platform
            current_category = None
            category_count   = 0
            console.print()
            console.print(Rule(
                f"[bold white] Release: [yellow]{e.release}[/yellow]  |  "
                f"Platform: [cyan]{e.platform}[/cyan] [/bold white]",
                style="white",
            ))

        # New category
        if e.category != current_category:
            _flush_table()
            current_category = e.category
            category_count   = 0
            current_tbl = Table(
                title=f"[bold cyan]{e.category}[/bold cyan]",
                title_justify="left",
                box=box.SIMPLE_HEAD,
                show_edge=False,
                pad_edge=True,
                header_style="bold dim",
            )
            current_tbl.add_column("Release Date", style="green",      width=14)
            current_tbl.add_column("Fix ID",        style="white",      no_wrap=False)

        # Truncation
        if limit is not None and category_count >= limit:
            if category_count == limit:
                remaining = totals.get((e.release, e.platform, e.category), 0) - limit
                if remaining > 0 and current_tbl is not None:
                    current_tbl.add_row(
                        "[dim]...[/dim]",
                        f"[dim]{remaining} more — use [bold]--show-all[/bold] to see all[/dim]",
                    )
            category_count += 1
            continue

        if current_tbl is not None:
            current_tbl.add_row(e.release_date, e.fix_id)
        category_count += 1

    _flush_table()


def _print_table_newest(
    entries: list[FixEntry],
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> None:
    """Print only the single newest fix per release+platform+category."""
    newest: dict[tuple, FixEntry] = {}
    for e in entries:
        key = (e.release, e.platform, e.category)
        if key not in newest:
            newest[key] = e
        elif e.date_obj is not None:
            existing = newest[key].date_obj
            if existing is None or e.date_obj > existing:
                newest[key] = e

    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=True,
        header_style="bold dim",
    )
    tbl.add_column("Release",      style="yellow",  width=9)
    tbl.add_column("Platform",     style="cyan",    width=10)
    tbl.add_column("Category",     style="white",   width=40)
    tbl.add_column("Release Date", style="green",   width=14)
    tbl.add_column("Fix ID",       style="white",   no_wrap=False)

    for e in sorted(newest.values(), key=lambda e: _sort_key(e, release_order, platform_order)):
        tbl.add_row(e.release, e.platform, e.category, e.release_date, e.fix_id)

    console.print()
    console.print(tbl)


def _write_csv(
    entries: list[FixEntry],
    path: str,
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> bool:
    """Write entries to CSV. Returns True on success, False on failure."""
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Release", "Platform", "Category", "Release Date", "Fix ID"])
            for e in sorted(entries, key=lambda e: _sort_key(e, release_order, platform_order)):
                w.writerow([e.release, e.platform, e.category, e.release_date, e.fix_id])
    except OSError as exc:
        _log("ERR", f"Could not write CSV to [bold]{path}[/bold]: {exc}", file=sys.stderr)
        return False
    _log("OK", f"Results written to [bold]{path}[/bold]")
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="List IBM Fix Central patches for any IBM product",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog="""
Examples:
  %(prog)s guardium
  %(prog)s "db2" --newest-only
  %(prog)s guardium --releases 12.2 12.x --platforms Linux
  %(prog)s guardium --category "KTAP Bundle" "Database Agent (STAP, GIM and CAS)"
  %(prog)s guardium --output fixes.csv
        """,
    )
    parser.add_argument(
        "product_query",
        metavar="PRODUCT",
        help="Product name to search for on Fix Central (e.g. guardium, db2, mq)",
    )
    parser.add_argument(
        "--releases", nargs="+", default=None,
        metavar="RELEASE",
        help="Releases to check (default: all, discovered live). e.g. --releases 12.2 12.x",
    )
    parser.add_argument(
        "--platforms", nargs="+", default=None,
        metavar="PLATFORM", dest="platforms",
        help='Platforms to check (default: all, discovered live). e.g. --platforms Linux Windows "IBM i"',
    )
    parser.add_argument(
        "--category", nargs="+", default=None, dest="categories",
        metavar="CAT",
        help=(
            "Filter to specific category name(s) — must match exactly. "
            'Quote multi-word names: --category "KTAP Bundle". '
            "Run without this flag to see all available categories."
        ),
    )
    parser.add_argument(
        "--newest-only", action="store_true",
        help="Show only the single newest fix per release+platform+category",
    )
    parser.add_argument(
        "--output", metavar="FILE", default=None,
        help="Write results to a CSV file",
    )
    parser.add_argument(
        "--show-all", action="store_true",
        help="Show all fixes per category (default: cap at 10)",
    )
    parser.add_argument(
        "--page-timeout", type=int, default=90, metavar="SECS",
        help="Seconds to wait for Fix Central page to render (default: 90)",
    )
    args = parser.parse_args()

    # ── Header ───────────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        "[bold white]IBM Fix Central Patch Checker[/bold white]",
        style="bold cyan",
        expand=False,
    ))
    console.print()

    # ── Step 1: search for products ──────────────────────────────────────────
    _log("INFO", f"Searching Fix Central for: '[yellow]{args.product_query}[/yellow]'")

    products = search_products(args.product_query)

    # If the full query returned nothing, the user may have passed an exact
    # product name (as suggested by the tip).  Fix Central's search works on
    # short keywords, not full names.  Derive shorter fallback keywords and
    # retry, then filter results to the exact name.
    if not products:
        query_lower = args.product_query.lower()
        # Strip parentheticals and "IBM " prefix to get a base phrase.
        base = re.sub(r'\s*\(.*?\)', '', args.product_query).strip()
        base = re.sub(r'^IBM\s+', '', base, flags=re.IGNORECASE).strip()
        base_words = base.split()
        # Collect the parenthetical content (e.g. "Tivoli") as a further candidate.
        paren_match = re.search(r'\(([^)]+)\)', args.product_query)
        paren_keyword = paren_match.group(1).strip() if paren_match else ""

        # Build an ordered list of candidate keywords to try, from most
        # specific to least, skipping duplicates and the original full query.
        seen_kw: set[str] = {query_lower}
        fallback_keywords: list[str] = []
        for n in (3, 2):
            kw = " ".join(base_words[-n:]) if len(base_words) >= n else " ".join(base_words)
            if kw.lower() not in seen_kw:
                seen_kw.add(kw.lower())
                fallback_keywords.append(kw)
        if paren_keyword and paren_keyword.lower() not in seen_kw:
            fallback_keywords.append(paren_keyword)

        # Also accept a candidate whose name matches the query with parentheticals
        # stripped from either side (handles minor display-name variations).
        base_lower = base.lower()

        def _is_name_match(display: str) -> bool:
            dl = display.lower()
            if dl == query_lower:
                return True
            # Strip parentheticals from the candidate and compare.
            dl_stripped = re.sub(r'\s*\(.*?\)', '', display).strip().lower()
            # Also strip a leading "ibm " from the candidate for comparison.
            dl_no_ibm = re.sub(r'^ibm\s+', '', dl_stripped).strip()
            return dl_stripped == query_lower or dl_no_ibm == base_lower

        for kw in fallback_keywords:
            _log("INFO", f"Retrying with derived keyword: '[yellow]{kw}[/yellow]'")
            candidates = search_products(kw)
            matched = [p for p in candidates if _is_name_match(p.display_name)]
            if matched:
                products = matched
                break

    if not products:
        _log("WARN", f"No products found for '[yellow]{args.product_query}[/yellow]'. "
             "Check the spelling or try a shorter term.", file=sys.stderr)
        return 1

    # ── Step 2: let user pick a product ──────────────────────────────────────
    chosen = prompt_product_choice(products, args.product_query)
    if chosen is None:
        _log("WARN", "No product selected — exiting.")
        return 1

    # ── Summary panel ────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Run Configuration[/bold cyan]", style="cyan"))
    _log("INFO", f"Product  : [bold white]{chosen.display_name}[/bold white]")
    # Only show the product tip if the user searched by a short/partial term —
    # the full combined tip (with releases + platforms) is shown later after prompts.
    if chosen.display_name.lower() != args.product_query.lower():
        _log("INFO",
             f"Tip: next time use [bold cyan]python {_script_name()} "
             f'"{chosen.display_name}"[/bold cyan] to go straight to this product.')
    if args.releases:
        _log("INFO", f"Releases : [yellow]{' '.join(args.releases)}[/yellow]")
    else:
        _log("INFO", "Releases : [dim](will discover live — you will be prompted to choose)[/dim]")
    if args.platforms:
        _log("INFO", f"Platforms: [cyan]{' '.join(args.platforms)}[/cyan]")
    else:
        _log("INFO", "Platforms: [dim](will discover live — you will be prompted to choose)[/dim]")
    console.print()

    # ── Step 3: discover releases + scrape ───────────────────────────────────
    discover_releases  = not bool(args.releases)
    discover_platforms = not bool(args.platforms)
    releases  = list(args.releases)  if args.releases  else []
    platforms = list(args.platforms) if args.platforms else []

    if discover_releases or discover_platforms:
        _log("INFO", "Discovering available releases and platforms from Fix Central ...")
    else:
        _log("INFO", "Validating releases and platforms against Fix Central ...")

    entries, releases, platforms = fetch_fix_central(
        chosen,
        releases,
        platforms,
        categories=args.categories,
        page_timeout=args.page_timeout,
        headless=True,
        discover_releases=discover_releases,
        discover_platforms=discover_platforms,
    )

    # fetch_fix_central already logs a specific WARN before returning empty
    # lists, so these checks only guard against unexpected empty returns.
    if not releases or not platforms:
        return 1

    release_order  = {r: i for i, r in enumerate(releases)}
    platform_order = {p: i for i, p in enumerate(platforms)}

    if not entries:
        _log("WARN", "No fixes found.")
        return 1

    console.print()
    console.print(Rule(style="cyan"))
    _log("OK", f"Total: [bold green]{len(entries)}[/bold green] fixes found")
    console.print(Rule(style="cyan"))

    # ── Step 4: output ────────────────────────────────────────────────────────
    if args.newest_only:
        _log("INFO", "Newest fix per release, platform and category:")
        _print_table_newest(entries, release_order, platform_order)
    else:
        _print_table(entries, limit=None if args.show_all else DEFAULT_LIMIT,
                     release_order=release_order, platform_order=platform_order)

    if args.output:
        if not _write_csv(entries, args.output, release_order, platform_order):
            return 1

    console.print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
