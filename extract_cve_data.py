#!/usr/bin/env python3
"""Extract and aggregate CVE data by vendor, product, and CVSS severity."""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CVE_DIR = SCRIPT_DIR / "cvelistV5" / "cves"
OUTPUT_FILE = SCRIPT_DIR / "cve_summary.json"

SEVERITY_RANGES = {
    "NONE": (0.0, 0.0),
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


def classify_severity(score):
    if score == 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


def extract_cvss(cve):
    """Extract best available CVSS score and severity from a CVE record."""
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", [])

    # Try CNA metrics first
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                score = metric[key].get("baseScore")
                severity = metric[key].get("baseSeverity", "").upper()
                if score is not None:
                    if not severity:
                        severity = classify_severity(score)
                    return float(score), severity

    # Fallback to ADP metrics
    for adp in adp_list:
        for metric in adp.get("metrics", []):
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
                if key in metric:
                    score = metric[key].get("baseScore")
                    severity = metric[key].get("baseSeverity", "").upper()
                    if score is not None:
                        if not severity:
                            severity = classify_severity(score)
                        return float(score), severity

    return None, None


def extract_affected(cve):
    """Extract vendor/product pairs from a CVE record."""
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})
    pairs = []

    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "").strip()
        product = affected.get("product", "").strip()
        if vendor and product and vendor.lower() != "n/a" and product.lower() != "n/a":
            pairs.append((vendor, product))

    # Fallback to ADP affected if CNA had nothing useful
    if not pairs:
        for adp in containers.get("adp", []):
            for affected in adp.get("affected", []):
                vendor = affected.get("vendor", "").strip()
                product = affected.get("product", "").strip()
                if vendor and product and vendor.lower() != "n/a" and product.lower() != "n/a":
                    pairs.append((vendor, product))

    return pairs


def extract_year(cve):
    """Extract publication year from CVE metadata."""
    meta = cve.get("cveMetadata", {})
    date_pub = meta.get("datePublished", "")
    if date_pub and len(date_pub) >= 4:
        try:
            return int(date_pub[:4])
        except ValueError:
            pass
    # Fallback: parse from CVE ID
    cve_id = meta.get("cveId", "")
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except ValueError:
                pass
    return None


def main():
    # vendor_year_severity[vendor][year][severity] = count
    vendor_year_severity = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    # product_year_severity[(vendor, product)][year][severity] = count
    product_year_severity = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    # vendor_total[vendor] = total CVE count
    vendor_total = defaultdict(int)
    # product_total[(vendor, product)] = total CVE count
    product_total = defaultdict(int)
    # year_severity[year][severity] = count (overall)
    year_severity = defaultdict(lambda: defaultdict(int))

    total_files = 0
    parsed = 0
    with_cvss = 0
    with_vendor = 0
    skipped = 0

    year_dirs = sorted([d for d in CVE_DIR.iterdir() if d.is_dir()])

    for year_dir in year_dirs:
        year_name = year_dir.name
        try:
            int(year_name)
        except ValueError:
            continue

        print(f"Processing {year_name}...", end=" ", flush=True)
        year_count = 0

        for bucket_dir in sorted(year_dir.iterdir()):
            if not bucket_dir.is_dir():
                continue
            for cve_file in bucket_dir.iterdir():
                if not cve_file.name.endswith(".json"):
                    continue
                total_files += 1
                try:
                    with open(cve_file, "r") as f:
                        cve = json.load(f)
                except (json.JSONDecodeError, IOError):
                    skipped += 1
                    continue

                state = cve.get("cveMetadata", {}).get("state", "")
                if state != "PUBLISHED":
                    skipped += 1
                    continue

                parsed += 1
                year = extract_year(cve)
                score, severity = extract_cvss(cve)
                pairs = extract_affected(cve)

                if score is not None:
                    with_cvss += 1

                if pairs:
                    with_vendor += 1

                if year and severity and pairs:
                    year_count += 1
                    for vendor, product in pairs:
                        vendor_year_severity[vendor][year][severity] += 1
                        product_year_severity[f"{vendor}|||{product}"][year][severity] += 1
                        vendor_total[vendor] += 1
                        product_total[f"{vendor}|||{product}"] += 1

                if year and severity:
                    year_severity[year][severity] += 1

        print(f"{year_count} records with full data", flush=True)

    # Get top 20 vendors by total CVE count
    top_vendors = sorted(vendor_total.items(), key=lambda x: -x[1])[:20]
    top_vendor_names = [v[0] for v in top_vendors]

    # Get top 30 products by total CVE count
    top_products = sorted(product_total.items(), key=lambda x: -x[1])[:30]
    top_product_keys = [p[0] for p in top_products]

    # Build output
    all_years = sorted(set(
        y for d in [year_severity, *vendor_year_severity.values()]
        for y in d.keys()
    ))

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    output = {
        "meta": {
            "totalFiles": total_files,
            "parsed": parsed,
            "withCvss": with_cvss,
            "withVendor": with_vendor,
            "skipped": skipped,
        },
        "years": all_years,
        "severities": severities,
        "overall": {},
        "vendors": {},
        "products": {},
    }

    # Overall year/severity
    for year in all_years:
        output["overall"][str(year)] = {s: year_severity[year].get(s, 0) for s in severities}

    # Top vendors
    for vendor in top_vendor_names:
        output["vendors"][vendor] = {
            "total": vendor_total[vendor],
            "data": {},
        }
        for year in all_years:
            output["vendors"][vendor]["data"][str(year)] = {
                s: vendor_year_severity[vendor][year].get(s, 0) for s in severities
            }

    # Top products
    for pkey in top_product_keys:
        vendor, product = pkey.split("|||", 1)
        label = f"{vendor} - {product}"
        output["products"][label] = {
            "total": product_total[pkey],
            "vendor": vendor,
            "product": product,
            "data": {},
        }
        for year in all_years:
            output["products"][label]["data"][str(year)] = {
                s: product_year_severity[pkey][year].get(s, 0) for s in severities
            }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f)

    print(f"\nDone! Summary written to {OUTPUT_FILE}")
    print(f"  Total files: {total_files}")
    print(f"  Parsed (PUBLISHED): {parsed}")
    print(f"  With CVSS: {with_cvss}")
    print(f"  With vendor/product: {with_vendor}")
    print(f"  Top vendors: {', '.join(top_vendor_names[:5])}...")


if __name__ == "__main__":
    main()
