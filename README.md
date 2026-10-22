# CVE Vendor Comparison Dashboard

A self-contained HTML dashboard for comparing published CVEs across vendors and products, built from the [cvelistV5](https://github.com/CVEProject/cvelistV5) repository.

## Opening the dashboard

Open `cve_dashboard.html` in any modern browser. No server required — all data is embedded inline.

## Features

### Vendor selection

- **Search bar** — Type to search across 12,000+ vendors. Select up to 8 at a time.
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

- **Preset ranges** — 7d, 14d, 30d (default), 180d, 360d. Relative to the latest CVE date in the data.
- **Custom date range** — Two date pickers with an Apply button. Dates are constrained to the available data window and validated (start must be before end). The extraction processes the last ~400 days of CVE data, so the earliest selectable date is approximately 400 days before the most recent extraction run.
- **Grouping** — Daily (default), Weekly, Monthly, Quarterly. Controls how data points are bucketed on the x-axis.

### Severity toggles

Four toggle buttons (Critical, High, Medium, Low) filter which CVSS severity levels are included in the chart and summary card counts. At least one must remain active. These do not affect the product picker or detail table.

### Product picker

Below the chart, one dropdown per selected vendor lists all products for that vendor (sorted by total CVE count). Features:

- **Search** — Filter products by name within each dropdown.
- **Checkboxes** — Select individual products. The dropdown stays open while selecting.
- **Clear all** — Deselects all products for that vendor (respects the current search filter).
- When products are selected, the chart switches to stacked mode, and the summary cards and detail table filter to only show CVEs affecting those products.
- When no products are selected, all products are included.

### CVE detail table

A paginated table below the product picker showing individual CVE records. Features:

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

1. **`extract_daily.py`** — Scans CVE JSON files from the last ~400 days, extracts vendor, product, CVSS score, and severity, and writes `cve_vendor_daily.json`.
2. **Data injection** — Replaces the embedded JSON in `cve_dashboard.html` with the updated data.

The extraction takes roughly one minute for ~160,000 files.

### What the extraction produces

`cve_vendor_daily.json` contains:

| Key | Description |
|-----|-------------|
| `meta` | File counts, date range, vendor count |
| `vendors` | All vendors sorted by CVE count, with totals |
| `products` | Indexed product name lookup array |
| `daily` | Per-vendor daily severity counts (keyed by vendor index) |
| `records` | Per-vendor individual CVE records (keyed by vendor index) |

Each CVE record is: `[cveId, date, [productIndices], severityIndex, score]`

## Directory structure

```
cve/
├── cve_dashboard.html          # Self-contained dashboard (HTML + CSS + JS + embedded data)
├── extract_daily.py            # Python script to extract and aggregate CVE data
├── refresh_dashboard.sh        # Shell script to re-extract data and update the dashboard
├── cve_vendor_daily.json       # Generated intermediate data file (not checked in)
├── cve_summary.json            # Generated yearly summary data (not checked in)
├── extract_cve_data.py         # Yearly aggregation script (used to generate cve_summary.json)
├── README.md
└── cvelistV5/                  # Clone of the CVE list repository
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
| `extract_daily.py` | Extracts daily vendor/product/severity data from CVE JSON files |
| `refresh_dashboard.sh` | Runs extraction and injects updated data into the dashboard |
| `cve_vendor_daily.json` | Intermediate data produced by `extract_daily.py` |
| `cvelistV5/` | Git clone of [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) |

### Generated files

These are produced by the extraction scripts and should not be edited manually:

- `cve_vendor_daily.json` — Daily-resolution vendor/product data (last ~400 days)
- `cve_summary.json` — Yearly aggregation across all years (used by the original yearly dashboard, not the current one)
