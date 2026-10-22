# CVE Vendor Comparison Dashboard

A self-contained HTML dashboard for comparing published CVEs across vendors and products, built from the [cvelistV5](https://github.com/CVEProject/cvelistV5) repository.

## Opening the dashboard

Open `cve_dashboard.html` in any modern browser. No server required — all data is embedded inline. The file is fully self-contained (HTML + CSS + JS + embedded JSON data).

## Features

### Vendor selection

- **Search bar** — Type to search across 27,000+ vendors. Select up to 8 at a time.
- **Vendor chips** — Selected vendors appear as color-coded chips above the chart. Click the × to remove one.
- Default vendors: Arista Networks, Cisco, Hewlett Packard Enterprise (HPE), Juniper Networks.

### Summary cards

One card per selected vendor, displayed above the chart. Each card shows:

- Total CVE count within the selected time range
- CVSS severity breakdown (Critical, High, Medium, Low)
- Date of the most recent CVE disclosure

Summary cards respect both the selected time range and any product filters applied.

### Bar chart

- **Grouped bars** — One bar per vendor per time bucket when no products are selected.
- **Stacked bars** — When products are selected in the product picker, bars stack by product within each vendor group. Products from the same vendor share a color family.
- Hover tooltip shows the count per dataset at each time bucket.

### Time controls

- **Preset ranges** — 7d, 14d, 30d (default), 180d, 1y, 2y, 5y, All. Relative to the latest CVE date in the data.
- **Custom date range** — Two date pickers with an Apply button. Dates are constrained to the available data window and validated (start must be before end).
- **Grouping** — Daily (default), Weekly, Monthly, Quarterly, Yearly. Controls how data points are bucketed on the x-axis. Available groupings are constrained by the selected time range and the resolution of the underlying data (see tiered data below).

### Severity toggles

Four toggle buttons (Critical, High, Medium, Low) filter which CVSS severity levels are included in the chart and summary card counts. At least one must remain active. These do not affect the product picker or detail table.

### Product picker

Below the chart, one dropdown per selected vendor lists all products for that vendor (sorted by total CVE count). Product lists are derived from the daily tier (~400 days of individual CVE records), so only products with CVEs in that window appear. Features:

- **Search** — Filter products by name within each dropdown.
- **Checkboxes** — Select individual products. The dropdown stays open while selecting.
- **Clear all** — Deselects all products for that vendor (respects the current search filter).
- When products are selected, the chart switches to stacked mode, and the summary cards and detail table filter to only show CVEs affecting those products.
- When no products are selected, all products are included.

### CVE detail table

A paginated table below the product picker showing individual CVE records from the daily tier (last ~400 days). CVEs older than this window are reflected in the chart counts but do not appear in the table. Features:

- **Vendor tabs** — Color-coded tabs to switch between vendors. Switching tabs clears the search field.
- **Search** — Filter by CVE ID or product name.
- **Severity filter** — Dropdown to show all severities or a specific one.
- **Sortable columns** — Click any column header (CVE ID, Published, Product, Score, Severity) to sort.
- **Pagination** — 50 rows per page with page navigation.
- **CVE links** — Each CVE ID links to its record on cve.org.
- **Full product list** — All affected products are shown per CVE (up to 10, with "+N more" for outliers).
- The table respects the selected time range and product filters.

### Theme

- **Toggle button** — Switches between light and dark mode.
- **System default** — Follows the OS preference when no override is set.
- All controls, charts, and cards adapt to the selected theme.

## Updating the dashboard

The dashboard displays a snapshot of CVE data. To refresh it after new CVEs are published:

### 1. Pull the latest CVE data

```bash
git -C cvelistV5 pull
```

### 2. Run the refresh script

```bash
./refresh_dashboard.sh
```

This runs two steps:

1. **`extract_daily.py`** — Scans all CVE JSON files in `cvelistV5/`, extracts vendor, product, CVSS score, and severity, and writes `cve_vendor_daily.json`.
2. **Data injection** — Replaces the embedded JSON in `cve_dashboard.html` with the updated data.

### Caching

The extraction maintains a file-level cache (`cve_cache.json`) that stores parsed results keyed by file path and modification time. On subsequent runs, only new or modified CVE files are re-parsed. The first run processes all ~400,000+ files; subsequent runs typically complete in seconds.

### Tiered data

To keep the dashboard responsive while covering the full CVE history, data is stored at different resolutions depending on age:

| Tier | Time window | Resolution |
|------|-------------|------------|
| Daily | Last ~400 days | Per-day counts + individual CVE records |
| Weekly | 400 days – 2 years | Per-ISO-week aggregated counts |
| Monthly | 2 – 5 years | Per-month aggregated counts |
| Quarterly | 5+ years | Per-quarter aggregated counts |

Individual CVE records (for the detail table) are only available in the daily tier. Older tiers provide severity-bucketed counts for charting.

### What the extraction produces

`cve_vendor_daily.json` contains:

| Key | Description |
|-----|-------------|
| `meta` | File counts, date range, cutoff dates per tier, vendor count |
| `vendors` | All vendors sorted by CVE count (across all tiers), with totals |
| `products` | Indexed product name lookup array |
| `daily` | Per-vendor daily severity counts (keyed by vendor index) |
| `weekly` | Per-vendor weekly severity counts |
| `monthly` | Per-vendor monthly severity counts |
| `quarterly` | Per-vendor quarterly severity counts |
| `records` | Per-vendor individual CVE records (daily tier only, keyed by vendor index) |

Each CVE record is: `[cveId, date, [productIndices], severityIndex, score]`

## Directory structure

```
cve_viewer/
├── cve_dashboard.html          # Self-contained dashboard (HTML + CSS + JS + embedded data)
├── extract_daily.py            # Python script to extract and aggregate CVE data
├── refresh_dashboard.sh        # Shell script to re-extract data and update the dashboard
├── cve_vendor_daily.json       # Generated intermediate data file (not checked in)
├── cve_cache.json              # Generated file-level parse cache (not checked in)
├── cve_summary.json            # Generated yearly summary data (not checked in)
├── extract_cve_data.py         # Yearly aggregation script (used to generate cve_summary.json)
├── .gitignore
├── README.md
└── cvelistV5/                  # Clone of the CVE list repository (git-ignored)
    └── cves/
        ├── 1999/               # CVE files organized by year
        │   └── 0xxx/           # Bucketed by ID range (thousands)
        │       └── CVE-1999-0001.json
        ├── 2000/
        ├── ...
        ├── 2025/
        ├── 2026/
        ├── delta.json          # Recent change metadata
        └── deltaLog.json       # Change log
```

### Key files

| File | Purpose |
|------|---------|
| `cve_dashboard.html` | The dashboard — open in a browser, no server needed |
| `extract_daily.py` | Extracts and caches vendor/product/severity data from all CVE JSON files |
| `refresh_dashboard.sh` | Runs extraction and injects updated data into the dashboard |
| `cve_vendor_daily.json` | Intermediate tiered data produced by `extract_daily.py` |
| `cve_cache.json` | File-level parse cache for incremental extraction |
| `cvelistV5/` | Git clone of [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) |

### Generated files

These are produced by the extraction scripts and should not be edited manually:

- `cve_vendor_daily.json` — Tiered vendor/product data (daily, weekly, monthly, quarterly)
- `cve_cache.json` — Parse cache mapping file paths to extracted CVE data with modification timestamps
- `cve_summary.json` — Yearly aggregation across all years (used by the original yearly dashboard, not the current one)
