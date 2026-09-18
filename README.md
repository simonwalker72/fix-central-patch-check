# IBM Fix Central Patch Checker

A command-line tool that queries [IBM Fix Central](https://www.ibm.com/support/fixcentral/) and lists available patches for any IBM product, grouped by category and sorted by release date (newest first).

---

## How it works

1. **Product search** — queries Fix Central's search endpoint over plain HTTPS and presents matching products as a numbered list. If the exact product name is passed (e.g. from a previous tip), it is matched directly without prompting.
2. **Release & platform discovery** — launches a headless Chromium browser, navigates to the product's Fix Central page, and scrapes the release and platform dropdowns. Values are presented interactively if not supplied on the command line, or validated silently if they were.
3. **Fix scraping** — fetches the `selectFixes` page for each release × platform combination and parses the rendered HTML into a structured list of fixes (fix ID, release date, category).
4. **Output** — displays results in grouped rich tables in the terminal, or writes them to a CSV file.

---

## Prerequisites

**Python 3.10+**

---

## Setup

It is recommended to use a Python virtual environment to keep dependencies isolated.

### Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Once activated, your prompt will show (.venv).

### Install dependencies

```bash
pip install playwright rich
playwright install chromium
```

To deactivate the virtual environment when you are done:

```bash
deactivate
```

---

## Installation

No package installation required. Clone the repository, create a virtual environment, and install dependencies:

```bash
git clone https://github.com/simonwalker72/fix-central-patch-check.git
cd fix-central-patch-check
python -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install playwright rich
playwright install chromium
```

---

## Usage

### Basic syntax

```
python ibm_fc_patch_checker_cli.py PRODUCT [OPTIONS]
```

`PRODUCT` is a keyword or full product name. Partial keywords work — you will be prompted to choose from matching results.

### Options

| Flag | Description |
|---|---|
| `--releases RELEASE [...]` | One or more release versions to check. Discovered and prompted if omitted. |
| `--platforms PLATFORM [...]` | One or more platforms to check. Discovered and prompted if omitted. Quote multi-word names: `"IBM i"`. |
| `--category CAT [...]` | Filter to specific category name(s). Must match exactly — quote multi-word names. Omit to see all categories. |
| `--newest-only` | Show only the single newest fix per release, platform and category. |
| `--output FILE` | Write results to a CSV file instead of printing to the terminal. |
| `--show-all` | Show all fixes per category (default: cap at 10 per category). |
| `--page-timeout SECS` | Seconds to wait for Fix Central to render (default: 90). |

---

## Examples

### Search by keyword — interactive mode

Searches Fix Central for products matching `guardium` and prompts you to choose one, then prompts for a release and platform:

```bash
python ibm_fc_patch_checker_cli.py guardium
```

### Search by keyword — skip prompts

Passes releases and platforms directly to skip all interactive prompts:

```bash
python ibm_fc_patch_checker_cli.py guardium --releases 12.2 --platforms Linux
```

### Use the full product name

The tool always tips you with the exact product name and flags after an interactive run. Paste that command to skip the product selection prompt next time:

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 --platforms Linux
```

### Multiple releases and platforms

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" --releases 12.2 12.1 11.5 --platforms Linux Windows
```

### Platforms with spaces in the name

Quote multi-word platform names. Unquoted tokens are automatically rejoined if they match a known platform name:

```bash
# Quoted (recommended)
python ibm_fc_patch_checker_cli.py db2 --platforms "IBM i" Linux

# Unquoted — also works, rejoined automatically
python ibm_fc_patch_checker_cli.py db2 --platforms IBM i Linux
```

### Filter by category

Category names must match exactly. Quote multi-word names:

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" \
  --releases 12.2 --platforms Linux \
  --category "KTAP Bundle"
```

Multiple categories can be specified:

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" \
  --releases 12.2 --platforms Linux \
  --category "KTAP Bundle" "Database Agent (STAP, GIM and CAS)"
```

Run without `--category` to see all available category names for a product.

### Newest fix only

Shows one row per release/platform/category — the most recently released fix in each group:

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" \
  --releases 12.2 --platforms Linux \
  --newest-only
```

### Export to CSV

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" \
  --releases 12.2 12.1 \
  --platforms Linux Windows \
  --output guardium_fixes.csv
```

The CSV contains columns: `Release`, `Platform`, `Category`, `Release Date`, `Fix ID`.

### Show all results (no truncation)

By default, each category is capped at 10 fixes. Use `--show-all` to remove the cap:

```bash
python ibm_fc_patch_checker_cli.py "IBM Security Guardium" \
  --releases 12.2 --platforms Linux \
  --show-all
```

### WebSphere with a multi-word platform

```bash
python ibm_fc_patch_checker_cli.py "WebSphere Application Server" \
  --releases 9.0.5.29 \
  --platforms "Windows 64-bit, x86"
```

---

## Validation behaviour

When `--releases` or `--platforms` are supplied, the tool always validates them against the live Fix Central dropdown before fetching:

- **Unknown values** produce a warning listing what is valid:
  ```
  [WARN] Unknown platform(s): Windwos. Valid platforms: AIX, Linux, Windows, z/OS, ...
  ```
- **Partially valid** input: valid values are used, invalid ones are dropped.
- **All invalid**: the tool exits with a clear message rather than hanging.
- **Multi-word tokens** split by the shell (e.g. `IBM i` → `["IBM", "i"]`) are automatically rejoined before validation.

---

## Output format

### Terminal (default)

Results are grouped by release/platform, then by category. Each category is a table with `Release Date` and `Fix ID` columns:

```
──────────────────── Release: 12.2  |  Platform: Linux ────────────────────
KTAP Bundle
 Release Date     Fix ID
────────────────────────────────────────────────────────
 2025/06/15       guardium-ktap-12.2.0.100-rh8-x86_64
 2025/03/10       guardium-ktap-12.2.0.99-rh8-x86_64
 ...              8 more — use --show-all to see all
```

### CSV

When `--output` is used, a UTF-8 CSV is written with the header:

```
Release,Platform,Category,Release Date,Fix ID
```

---

## Notes

- **No IBM credentials required.** The tool only accesses publicly available Fix Central pages.
- **Network access required.** All data is fetched live from `www.ibm.com`.
- **Chromium is used for JavaScript-rendered pages.** Fix Central's product and fix pages require JS execution to populate dropdowns and render fix tables. The browser always runs headlessly.
- **Category names are case-sensitive.** Run without `--category` once to see exact names, then use them in subsequent runs.
- **The tool does not cache results.** Every run fetches fresh data from Fix Central.

---

## License

MIT
