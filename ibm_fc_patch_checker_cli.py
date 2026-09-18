#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IBM Fix Central Patch Checker
==============================
Version: v1.0 (2026-09-18)

Lists available fixes for any IBM product on Fix Central, grouped by category
and sorted by release date (newest first).

Usage
-----
  python3 ibm_fc_patch_checker_cli.py websphere
  python3 ibm_fc_patch_checker_cli.py db2
  python3 ibm_fc_patch_checker_cli.py guardium --releases 12.2 12.x
  python3 ibm_fc_patch_checker_cli.py guardium --platforms Linux
  python3 ibm_fc_patch_checker_cli.py guardium --newest-only
  python3 ibm_fc_patch_checker_cli.py guardium --output fixes.csv
  python3 ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux
  python3 ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux --category "KTAP Bundle"
  python3 ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux --category "Database Agent (STAP, GIM and CAS)"
  python3 ibm_fc_patch_checker_cli.py "WebSphere Application Server" --releases 9.0.5.29 --platforms "Windows 64-bit, x86"

Requirements
------------
  Python 3.10+ (Standard library only; no external packages or browsers required)
"""

import argparse
import csv
import html as html_lib
import http.cookiejar
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

# Ensure standard output and standard error streams handle UTF-8 characters cleanly
# across diverse platforms and Windows terminal code pages (e.g. cp1252/cp437).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

__version__ = "1.0"
__date__ = "2026-09-18"

# ---------------------------------------------------------------------------
# ANSI Color & Terminal Formatting (Zero external dependencies)
# ---------------------------------------------------------------------------

# On Windows 10/11, enable Virtual Terminal Processing on the console handles
# so standard ANSI escape sequences (\033[...m) render natively in CMD/PowerShell.
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # Win32 Constants:
        #   STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
        #   ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        for handle_id in (-11, -12):
            h = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        # Fallback gracefully if running in a restricted sandbox or older Windows environment
        pass


def _is_tty(file=None) -> bool:
    stream = file if file is not None else sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def _style(text: str, *codes: str, is_err: bool = False) -> str:
    target_stream = sys.stderr if is_err else sys.stdout
    if not _is_tty(target_stream):
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def _bold(text: str, is_err: bool = False) -> str:
    return _style(text, "1", is_err=is_err)

def _cyan(text: str, is_err: bool = False) -> str:
    return _style(text, "36", is_err=is_err)

def _bold_cyan(text: str, is_err: bool = False) -> str:
    return _style(text, "1", "36", is_err=is_err)

def _yellow(text: str, is_err: bool = False) -> str:
    return _style(text, "33", is_err=is_err)

def _green(text: str, is_err: bool = False) -> str:
    return _style(text, "32", is_err=is_err)

def _red(text: str, is_err: bool = False) -> str:
    return _style(text, "31", is_err=is_err)

def _bold_red(text: str, is_err: bool = False) -> str:
    return _style(text, "1", "31", is_err=is_err)

def _dim(text: str, is_err: bool = False) -> str:
    return _style(text, "2", is_err=is_err)

def _steel_blue(text: str, is_err: bool = False) -> str:
    # 38;5;67 renders a muted steel-blue color (matches rich color(67))
    return _style(text, "38", "5", "67", is_err=is_err)


def _term_width() -> int:
    return min(shutil.get_terminal_size((80, 24)).columns, 100)


def _print_panel(title: str) -> None:
    width = len(title) + 4
    print(f"\n{_bold_cyan('┌' + '─' * (width - 2) + '┐')}")
    print(f"{_bold_cyan('│')} {_bold(title)} {_bold_cyan('│')}")
    print(f"{_bold_cyan('└' + '─' * (width - 2) + '┘')}\n")


def _print_rule(title: str = "", style_fn=_cyan) -> None:
    w = _term_width()
    if not title:
        print(style_fn("─" * w))
        return
    plain_title = re.sub(r'\033\[[0-9;]*m', '', title)
    title_len = len(plain_title) + 2
    if title_len >= w:
        print(title)
        return
    side = max((w - title_len) // 2, 1)
    right_side = max(w - side - title_len, 1)
    print(f"{style_fn('─' * side)} {title} {style_fn('─' * right_side)}")


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def _log(level: str, msg: str, *, end: str = "\n", file=None) -> None:
    """Print a timestamped log line: [HH:MM:SS] [LEVEL] msg"""
    ts = datetime.now().strftime("%H:%M:%S")
    is_err = (file is sys.stderr)
    if level == "INFO":
        lvl_styled = _steel_blue(level, is_err=is_err)
    elif level == "OK":
        lvl_styled = _green(level, is_err=is_err)
    elif level == "WARN":
        lvl_styled = _yellow(level, is_err=is_err)
    elif level == "ERR":
        lvl_styled = _bold_red(level, is_err=is_err)
    else:
        lvl_styled = level
    line = f"{_dim(f'[{ts}]', is_err=is_err)} [{lvl_styled}] {msg}"
    print(line, end=end, file=file or sys.stdout, flush=True)


# ---------------------------------------------------------------------------
# Constants & Fix Central Endpoints
# ---------------------------------------------------------------------------

# Security guardrail: Only requests to this trusted host are permitted
_FC_TRUSTED_HOST     = "www.ibm.com"

# Endpoint 1: Product search by keyword
_FC_FIND_URL         = "https://www.ibm.com/support/fixcentral/find?text={query}"

# Endpoint 2: Product options page (initial releases dropdown)
_FC_VERSIONS_BASE    = "https://www.ibm.com/support/fixcentral/options?selectionBean.selectedTab=find&selection={selection}"

# Endpoint 3: AJAX dynamic platform dropdown query for a given release
_FC_AJAX_OPTIONS_URL = "https://www.ibm.com/support/fixcentral/ajaxOptions"

# Endpoint 4: Select fixes page (GET for session initialization, POST with showStatus=false for results)
_FC_SELECT_FIXES_URL = (
    "https://www.ibm.com/support/fixcentral/swg/selectFixes"
    "?parent={parent}"
    "&product={product}"
    "&release={release}"
    "&platform={platform}"
    "&function=all"
)

# Standard desktop browser user-agent header to ensure consistent server-side rendering
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_MAX_FIX_ID_LEN = 200


def _script_name() -> str:
    """Return the invoked script name for display in copy-pasteable CLI tips."""
    return os.path.basename(sys.argv[0])


# ---------------------------------------------------------------------------
# Security & Sanitization Helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != _FC_TRUSTED_HOST:
        raise ValueError(
            f"Refusing to load untrusted URL: {url!r}  "
            f"(expected https://{_FC_TRUSTED_HOST}/...)"
        )


def _sanitise_fix_id(raw: str) -> str:
    """Validate and sanitize a fix ID string parsed from HTML input checkboxes.
    
    Ensures fix IDs start with an alphanumeric character and contain only safe
    characters (letters, digits, dots, hyphens, underscores). Prevents terminal
    injection or CSV formula injection vulnerabilities.
    """
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
    raw_selection: str = ""


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
# Product search  (plain HTTP)
# ---------------------------------------------------------------------------

def search_products(query: str, timeout: int = 15) -> list[ProductMatch]:
    """Query Fix Central's find endpoint and parse all matching product taxonomy entries.
    
    Fix Central encodes hierarchy into the `selection` query parameter:
      e.g. `selection=ibm/WebSphere/WebSphere Application Server`
           parent  = `ibm~WebSphere` (slashes and spaces converted to tildes)
           product = `ibm/WebSphere/WebSphere+Application+Server`
    """
    url = _FC_FIND_URL.format(query=urllib.parse.quote(query))
    _validate_url(url)

    req = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        _log("WARN", f"Product search failed (HTTP {exc.code} {exc.reason})", file=sys.stderr)
        return []
    except (urllib.error.URLError, OSError) as exc:
        _log("WARN", f"Product search network error: {exc}", file=sys.stderr)
        return []

    seen_names: set[str] = set()
    products: list[ProductMatch] = []
    # Match links containing selection parameters in the HTML response
    for m in re.finditer(
        r'<a\s+href="[^"]*selection=([^"&]+)"[^>]*>(.*?)</a>',
        html, re.DOTALL
    ):
        raw_selection = urllib.parse.unquote_plus(m.group(1))
        display = html_lib.unescape(re.sub(r'<[^>]+>', '', m.group(2))).strip()
        if not display or display.lower() in seen_names:
            continue
        seen_names.add(display.lower())

        # Split hierarchical selection strings if a semicolon delimiter is present
        if ";" in raw_selection:
            parent_raw, product_raw = raw_selection.split(";", 1)
        else:
            parent_raw = raw_selection
            product_raw = raw_selection

        # Fix Central URL encoding rules (observed from browser):
        #   parent:  "/" → "~",  spaces → "~"
        #   product: "/" preserved, spaces → "+"
        parent  = parent_raw.replace("/", "~").replace(" ", "~")
        product = urllib.parse.quote(product_raw, safe="/").replace("%20", "+")
        selection_encoded = urllib.parse.quote(raw_selection, safe="")

        products.append(ProductMatch(
            display_name=display,
            selection=selection_encoded,
            parent=parent,
            product=product,
            raw_selection=raw_selection,
        ))

    return sorted(products, key=lambda p: p.display_name.lower())


# ---------------------------------------------------------------------------
# Product selection prompt
# ---------------------------------------------------------------------------

def prompt_product_choice(products: list[ProductMatch], query: str) -> Optional[ProductMatch]:
    if not products:
        _log("WARN", f"No products found matching '{query}'.", file=sys.stderr)
        return None

    print()
    _print_rule(f"{_bold_cyan('Products matching')} '{_yellow(query)}'", style_fn=_cyan)
    print()

    # Formatted table
    col_num = 4
    print(f"  {_dim('#'.rjust(col_num))}   {_bold_cyan('Product Name')}")
    print(f"  {_dim('─' * col_num)}   {_dim('─' * 55)}")
    for i, p in enumerate(products, 1):
        print(f"  {_dim(str(i).rjust(col_num))}   {p.display_name}")
    print()

    # If there is ONLY 1 product returned in total, auto-select it.
    if len(products) == 1:
        _log("INFO", f"Auto-selecting: {_bold(products[0].display_name)}")
        return products[0]

    while True:
        try:
            raw = input(f"  {_cyan('Select product number')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
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
# Release and Platform Discovery (HTTP / AJAX)
# ---------------------------------------------------------------------------

def _parse_releases_from_html(html: str) -> list[str]:
    """Parse release version strings from Fix Central select dropdown elements.
    
    Filters out placeholder elements like `-1` ('Select one') and `All`.
    """
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
    """Sort key that orders version strings numerically, newest first.
    
    e.g. "12.2" > "12.1" > "11.5" > "9.8.*" > "8.*"
    Non-numeric tokens (like "fp0", "*") sort cleanly after numeric parts.
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
    print()
    _print_rule(_bold_cyan("Available Releases"), style_fn=_cyan)
    print()

    col_num = 4
    print(f"  {_dim('#'.rjust(col_num))}   {_bold_cyan('Version')}")
    print(f"  {_dim('─' * col_num)}   {_dim('─' * 20)}")
    for i, r in enumerate(releases, 1):
        print(f"  {_dim(str(i).rjust(col_num))}   {r}")
    print()
    print(f"  Enter number(s) separated by spaces, or press {_bold('Enter')} to include all:")

    while True:
        try:
            raw = input(f"  {_cyan('>')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
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
        m = re.search(
            r'<select[^>]*id=["\']selectPlatform["\'][^>]*>(.*?)</select>',
            html, re.DOTALL
        )
    if not m:
        return []
    opts = re.findall(r'<option[^>]+value="([^"]+)"', m.group(1))
    return [v for v in opts if v not in ("-1", "All")]


def prompt_platform_choice(platforms: list[str]) -> list[str]:
    print()
    _print_rule(_bold_cyan("Available Platforms"), style_fn=_cyan)
    print()

    col_num = 4
    print(f"  {_dim('#'.rjust(col_num))}   {_bold_cyan('Platform')}")
    print(f"  {_dim('─' * col_num)}   {_dim('─' * 35)}")
    for i, p in enumerate(platforms, 1):
        print(f"  {_dim(str(i).rjust(col_num))}   {p}")
    print()
    print(f"  Enter number(s) separated by spaces, or press {_bold('Enter')} to include all:")

    while True:
        try:
            raw = input(f"  {_cyan('>')} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
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


def _create_http_opener() -> urllib.request.OpenerDirector:
    """Create a urllib OpenerDirector with an in-memory CookieJar.

    Fix Central requires stateful session cookies between the initial selectFixes
    GET request and the subsequent POST request (showStatus=false).
    """
    cookie_jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


def _fetch_releases_and_platforms_http(
    opener: urllib.request.OpenerDirector,
    product: ProductMatch,
    page_timeout: int,
) -> tuple[list[str], list[str]]:
    """Fetch the product options page via HTTP to get available releases,
    then invoke Fix Central's ajaxOptions endpoint to discover platforms for the release.

    Returns (releases, platforms).
    """
    versions_url = _build_versions_url(product)
    _validate_url(versions_url)
    _log("INFO", "Loading release and platform lists ...")
    t0 = time.monotonic()

    headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        req = urllib.request.Request(versions_url, headers=headers)
        with opener.open(req, timeout=page_timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        releases = _parse_releases_from_html(html)
        platforms = _parse_platforms_from_html(html)

        # Fix Central dynamically updates the platform dropdown via AJAX when a release is chosen.
        # Calling ajaxOptions with the first release ensures accurate platform values are retrieved.
        if releases:
            ajax_headers = {
                "User-Agent": _DEFAULT_USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": versions_url,
            }
            raw_sel = product.raw_selection or urllib.parse.unquote_plus(product.selection)
            ajax_payload = urllib.parse.urlencode({
                "selectionBean.selectedTab": "find",
                "selection": raw_sel,
                "release": releases[0],
                "platform": "All",
            }).encode("utf-8")
            ajax_req = urllib.request.Request(
                _FC_AJAX_OPTIONS_URL, data=ajax_payload, headers=ajax_headers
            )
            with opener.open(ajax_req, timeout=page_timeout) as ajax_resp:
                ajax_html = ajax_resp.read().decode("utf-8", errors="replace")
            ajax_plats = _parse_platforms_from_html(ajax_html)
            if ajax_plats:
                platforms = ajax_plats

    except urllib.error.HTTPError as exc:
        _log("WARN", f"Could not load version/platform lists (HTTP {exc.code} {exc.reason})", file=sys.stderr)
        return [], []
    except (urllib.error.URLError, OSError) as exc:
        _log("WARN", f"Could not load version/platform lists: {exc}", file=sys.stderr)
        return [], []

    elapsed = time.monotonic() - t0
    if not releases:
        _log("WARN", "Release dropdown found but no versions could be parsed.", file=sys.stderr)
        return [], []

    _log("OK", f"Found {_bold(str(len(releases)))} release(s) and "
         f"{_bold(str(len(platforms)))} platform(s) in {elapsed:.1f}s")
    return releases, platforms


def _fetch_fixes_for_combo(
    opener: urllib.request.OpenerDirector,
    url: str,
    timeout: int,
) -> str:
    """Fetch patch results for a release × platform combination.

    Fix Central uses a 2-step flow:
    1. GET selectFixes?…  — establishes session state and returns a page containing
       <form id="selectFixesForm">.
    2. POST selectFixes?… with payload showStatus=false — returns the full fix table.
    """
    _validate_url(url)
    headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # Step 1: GET to initialise session cookies
    get_req = urllib.request.Request(url, headers=headers)
    with opener.open(get_req, timeout=timeout) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    # If fixes are already in the response (cached / direct), return early
    if "selectFixesForm" not in html and (
        "type=\"checkbox\"" in html or "type='checkbox'" in html
    ):
        return html

    # Step 2: POST showStatus=false to get the rendered fix table
    post_headers = {
        "User-Agent": _DEFAULT_USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,
    }
    post_data = urllib.parse.urlencode({"showStatus": "false"}).encode("utf-8")
    post_req = urllib.request.Request(url, data=post_data, headers=post_headers)
    with opener.open(post_req, timeout=timeout) as post_resp:
        return post_resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Fix Central Page Parsing
# ---------------------------------------------------------------------------

def _parse_fc_date(raw: str) -> Optional[str]:
    """Parse date strings from Fix Central into normalized `YYYY/MM/DD` format.
    
    Handles both date formats present on Fix Central:
    - Long format: `Wed Sep 16 00:00:00 GMT 2026`
    - Short format: `09/16/2026`
    """
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


# Standard footer headings on Fix Central pages that must be ignored
_FC_IGNORED_HEADINGS = frozenset({
    "need support?", "about ibm", "ibm research", "industry",
    "partners", "engage with ibm", "select a country/region",
})


def _parse_fix_rows(rows: list[str], category: str,
                    release: str, platform: str) -> list[FixEntry]:
    """Parse a list of `<tr>` HTML table row strings into FixEntry objects."""
    entries: list[FixEntry] = []
    for row in rows:
        # Fix ID: any checkbox input whose value looks like a fix identifier
        # Handles attribute ordering variations (`type="checkbox" value="..."` vs `value="..." type="checkbox"`)
        fix_id_m = re.search(
            r'<input[^>]+type=["\']checkbox["\'][^>]+value="([A-Za-z0-9][^"]{1,190})"'
            r'|'
            r'<input[^>]+value="([A-Za-z0-9][^"]{1,190})"[^>]+type=["\']checkbox["\']',
            row, re.IGNORECASE,
        )
        if not fix_id_m:
            continue
        raw_id = html_lib.unescape(fix_id_m.group(1) or fix_id_m.group(2))
        try:
            fix_id = _sanitise_fix_id(raw_id)
        except ValueError:
            continue

        # Extract the release date from table cells (scanning backward from the end)
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
    """Parse the rendered Fix Central HTML into FixEntry objects.

    Two page layouts are handled automatically:
    - Categorized (e.g. Guardium): Fix rows sit inside `<h3>`-delimited sections.
    - Flat (e.g. WebSphere): Fix rows sit in a single table with no `<h3>` grouping.
    """
    # Categorized layout: split on <h3> headings
    sections = re.split(r'<h3[^>]*>', html)[1:]
    categorised_entries: list[FixEntry] = []
    for section in sections:
        h3_end = section.find("</h3>")
        if h3_end == -1:
            continue
        heading = html_lib.unescape(re.sub(r'<[^>]+>', '', section[:h3_end])).strip()
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
# CLI Argument & String Helpers
# ---------------------------------------------------------------------------

def _quote_if_needed(v: str) -> str:
    """Quote a string containing whitespace so it can be safely copy-pasted into shell commands."""
    return f'"{v}"' if " " in v else v


def _rejoin_multiword_tokens(tokens: list[str], known: list[str]) -> list[str]:
    """Greedily re-join CLI tokens that were split on spaces by the shell into multi-word names.

    e.g. CLI tokens `["IBM", "i", "Windows"]` with known platforms `["IBM i", "Windows"]`
         -> `["IBM i", "Windows"]`

    Unrecognized tokens are passed through unchanged so validation can report them.
    """
    known_lower = {v.lower(): v for v in known}
    result: list[str] = []
    i = 0
    while i < len(tokens):
        # Try longest match first (greedy match)
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
    discover_releases: bool = False,
    discover_platforms: bool = False,
) -> tuple[list[FixEntry], list[str], list[str]]:
    """Fetch Fix Central for each release × platform combination via HTTP.

    Returns (entries, releases_used, platforms_used).
    """
    opener = _create_http_opener()
    all_entries: list[FixEntry] = []
    select_fixes_url_template = _FC_SELECT_FIXES_URL.format(
        parent=product.parent,
        product=product.product,
        release="{release}",
        platform="{platform}",
    )

    disc_releases, disc_platforms = _fetch_releases_and_platforms_http(
        opener, product, page_timeout
    )
    if not disc_releases:
        _log("WARN",
             f"Could not load the Fix Central product page — "
             f"check your network connection or increase {_bold('--page-timeout')}.",
             file=sys.stderr)
        return [], [], []

    if discover_releases:
        releases = prompt_release_choice(disc_releases)
        print()
    else:
        # Re-join any multi-word release names split by the shell, then validate.
        releases = _rejoin_multiword_tokens(releases, disc_releases)
        valid_releases = [r for r in releases if r in disc_releases]
        invalid = [r for r in releases if r not in disc_releases]
        if invalid:
            _log("WARN",
                 f"Unknown release(s): {_yellow(', '.join(invalid))}. "
                 f"Valid releases: {_dim(', '.join(disc_releases))}",
                 file=sys.stderr)
        if not valid_releases:
            _log("WARN", "No valid releases to fetch — cannot continue.", file=sys.stderr)
            return [], [], []
        releases = valid_releases

    if discover_platforms:
        if not disc_platforms:
            _log("WARN",
                 f"Platform discovery returned no results — "
                 f"use {_bold('--platforms')} to specify explicitly.",
                 file=sys.stderr)
            return [], [], []
        platforms = prompt_platform_choice(disc_platforms)
        print()
    else:
        # Re-join any multi-word platform names split by the shell
        # (e.g. ["IBM", "i"] → ["IBM i"]) before validating.
        platforms = _rejoin_multiword_tokens(platforms, disc_platforms)
        valid_platforms = [p for p in platforms if p in disc_platforms]
        invalid = [p for p in platforms if p not in disc_platforms]
        if invalid:
            _log("WARN",
                 f"Unknown platform(s): {_cyan(', '.join(invalid))}. "
                 f"Valid platforms: {_dim(', '.join(disc_platforms))}",
                 file=sys.stderr)
        if not valid_platforms:
            _log("WARN", "No valid platforms to fetch — cannot continue.", file=sys.stderr)
            return [], [], []
        platforms = valid_platforms

    if discover_releases or discover_platforms:
        releases_str  = " ".join(_quote_if_needed(r) for r in releases)
        platforms_str = " ".join(_quote_if_needed(p) for p in platforms)
        tip_cmd = f'{sys.executable} {_script_name()} "{product.display_name}" --releases {releases_str} --platforms {platforms_str}'
        _log("INFO", f"Tip: next time run {_bold_cyan(tip_cmd)} to skip all prompts.")

    combos = list(dict.fromkeys((r, p) for r in releases for p in platforms))
    n = len(combos)
    print()
    _print_rule(
        f"{_bold_cyan('Fetching')} {_yellow(str(n))} {_bold_cyan('combination(s):')} "
        f"{', '.join(releases)}  |  {', '.join(platforms)}",
        style_fn=_cyan,
    )
    print()

    for idx, (release, platform) in enumerate(combos, 1):
        url = select_fixes_url_template.format(
            release=urllib.parse.quote(release),
            platform=urllib.parse.quote(platform),
        )

        _log("INFO",
             f"[{_dim(f'{idx}/{n}')}] {_yellow(release)} / {_cyan(platform)} ...",
             end="  ")
        t0 = time.monotonic()
        try:
            page_html = _fetch_fixes_for_combo(opener, url, timeout=page_timeout)
        except urllib.error.HTTPError as exc:
            print(_red(f"HTTP {exc.code}"))
            _log("WARN", f"Fix Central returned HTTP {exc.code} {exc.reason} for {release}/{platform}", file=sys.stderr)
            continue
        except (urllib.error.URLError, OSError) as exc:
            print(_red("ERROR"))
            _log("WARN", f"Network error for {release}/{platform}: {exc}", file=sys.stderr)
            continue

        entries = _parse_fc_page(page_html, release, platform)
        if categories:
            entries = [e for e in entries if e.category in categories]

        elapsed = time.monotonic() - t0
        print(f"{_green(f'{len(entries)} fixes')}  {_dim(f'({elapsed:.1f}s)')}")
        all_entries.extend(entries)

    return all_entries, releases, platforms


# ---------------------------------------------------------------------------
# Output Helpers (Formatted CLI Tables & CSV Export)
# ---------------------------------------------------------------------------

DEFAULT_LIMIT = 10


def _print_table(
    entries: list[FixEntry],
    limit: Optional[int] = DEFAULT_LIMIT,
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> None:
    """Print fixes grouped by release/platform -> category in clear aligned tables."""
    sorted_entries = sorted(entries, key=lambda e: _sort_key(e, release_order, platform_order))

    # Pre-calculate category totals to display "... N more" pagination messages
    totals: dict[tuple, int] = {}
    for e in sorted_entries:
        k = (e.release, e.platform, e.category)
        totals[k] = totals.get(k, 0) + 1

    current_release  = None
    current_platform = None
    current_category = None
    category_count   = 0

    for e in sorted_entries:
        # Start a new section when release or platform changes
        if e.release != current_release or e.platform != current_platform:
            current_release  = e.release
            current_platform = e.platform
            current_category = None
            category_count   = 0
            print()
            _print_rule(
                f"Release: {_yellow(e.release)}  |  Platform: {_cyan(e.platform)}",
                style_fn=_dim,
            )

        # Start a new table block when category changes
        if e.category != current_category:
            current_category = e.category
            category_count   = 0
            print(f"\n{_bold_cyan(e.category)}")
            print(f" {_dim('Release Date'.ljust(14))}   {_dim('Fix ID')}")
            print(f" {_dim('─' * 14)}   {_dim('─' * 55)}")

        # Enforce category truncation limit unless --show-all is specified
        if limit is not None and category_count >= limit:
            if category_count == limit:
                remaining = totals.get((e.release, e.platform, e.category), 0) - limit
                if remaining > 0:
                    print(f" {_dim('...'.ljust(14))}   {_dim(f'{remaining} more — use')} {_bold('--show-all')} {_dim('to see all')}")
            category_count += 1
            continue

        print(f" {_green(e.release_date.ljust(14))}   {e.fix_id}")
        category_count += 1


def _print_table_newest(
    entries: list[FixEntry],
    release_order:  Optional[dict[str, int]] = None,
    platform_order: Optional[dict[str, int]] = None,
) -> None:
    """Print only the single newest fix per release + platform + category group."""
    newest: dict[tuple, FixEntry] = {}
    for e in entries:
        key = (e.release, e.platform, e.category)
        if key not in newest:
            newest[key] = e
        elif e.date_obj is not None:
            existing = newest[key].date_obj
            if existing is None or e.date_obj > existing:
                newest[key] = e

    newest_list = list(newest.values())
    if not newest_list:
        return
    # Dynamically compute column widths to fit content cleanly without wrapping issues
    w_rel  = max(len("Release"),  *(len(e.release) for e in newest_list)) + 2
    w_plat = max(len("Platform"), *(len(e.platform) for e in newest_list)) + 2
    w_cat  = max(len("Category"), *(len(e.category) for e in newest_list)) + 2
    w_date = 14

    print()
    print(f" {_dim('Release'.ljust(w_rel))} {_dim('Platform'.ljust(w_plat))} {_dim('Category'.ljust(w_cat))} {_dim('Release Date'.ljust(w_date))} {_dim('Fix ID')}")
    print(f" {_dim('─' * w_rel)} {_dim('─' * w_plat)} {_dim('─' * w_cat)} {_dim('─' * w_date)} {_dim('─' * 35)}")

    for e in sorted(newest_list, key=lambda e: _sort_key(e, release_order, platform_order)):
        print(f" {_yellow(e.release.ljust(w_rel))} {_cyan(e.platform.ljust(w_plat))} {e.category.ljust(w_cat)} {_green(e.release_date.ljust(w_date))} {e.fix_id}")


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
        _log("ERR", f"Could not write CSV to {_bold(path)}: {exc}", file=sys.stderr)
        return False
    _log("OK", f"Results written to {_bold(path)}")
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"IBM Fix Central Patch Checker v{__version__} - List IBM Fix Central patches for any IBM product",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog="""
Examples:
  %(prog)s guardium
  %(prog)s "db2" --newest-only
  %(prog)s guardium --releases 12.2 12.x --platforms Linux
  %(prog)s "IBM Security Guardium" --category "KTAP Bundle" "Database Agent (STAP, GIM and CAS)"
  %(prog)s guardium --output fixes.csv
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s v{__version__} ({__date__})",
        help="Show program's version number and exit",
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
        help="Seconds to wait for Fix Central HTTP responses (default: 90)",
    )
    args = parser.parse_args()

    # ── Header ───────────────────────────────────────────────────────────────
    _print_panel(f"IBM Fix Central Patch Checker v{__version__}")

    # ── Step 1: search for products ──────────────────────────────────────────
    _log("INFO", f"Searching Fix Central for: '{_yellow(args.product_query)}'")

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
            _log("INFO", f"Retrying with derived keyword: '{_yellow(kw)}'")
            candidates = search_products(kw)
            matched = [p for p in candidates if _is_name_match(p.display_name)]
            if matched:
                products = matched
                break

    if not products:
        _log("WARN", f"No products found for '{_yellow(args.product_query)}'.", file=sys.stderr)
        return 1

    # ── Step 2: let user pick a product ──────────────────────────────────────
    chosen = prompt_product_choice(products, args.product_query)
    if chosen is None:
        _log("WARN", "No product selected — exiting.")
        return 1

    # ── Summary panel ────────────────────────────────────────────────────────
    print()
    _print_rule(_bold_cyan("Run Configuration"), style_fn=_cyan)
    _log("INFO", f"Product  : {_bold(chosen.display_name)}")
    if chosen.display_name.lower() != args.product_query.lower():
        tip_cmd = f'{sys.executable} {_script_name()} "{chosen.display_name}"'
        _log("INFO", f"Tip: next time use {_bold_cyan(tip_cmd)} to go straight to this product.")
    if args.releases:
        _log("INFO", f"Releases : {_yellow(' '.join(args.releases))}")
    else:
        _log("INFO", f"Releases : {_dim('(will discover live — you will be prompted to choose)')}")
    if args.platforms:
        _log("INFO", f"Platforms: {_cyan(' '.join(args.platforms))}")
    else:
        _log("INFO", f"Platforms: {_dim('(will discover live — you will be prompted to choose)')}")
    print()

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

    print()
    _print_rule(style_fn=_cyan)
    _log("OK", f"Total: {_bold(_green(str(len(entries))))} fixes found")
    _print_rule(style_fn=_cyan)

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

    print()
    all_cats = sorted(set(e.category for e in entries))
    if len(all_cats) > 1 and not args.categories:
        cat_examples = " ".join(_quote_if_needed(c) for c in all_cats[:2])
        _log("INFO", f"Tip: filter to specific categories with {_bold_cyan(f'--category {cat_examples}')}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        _log("WARN", "Aborted by user.")
        sys.exit(130)
