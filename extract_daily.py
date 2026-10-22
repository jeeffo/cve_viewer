#!/usr/bin/env python3
"""Extract daily CVE counts + individual CVE records by vendor for the last ~400 days."""

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CVE_DIR = SCRIPT_DIR / "cvelistV5" / "cves"
OUTPUT_FILE = SCRIPT_DIR / "cve_vendor_daily.json"

CUTOFF_DAYS = 400
SEV_IDX = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                score = metric[key].get("baseScore")
                sev = metric[key].get("baseSeverity", "").upper()
                if score is not None:
                    return float(score), sev or classify_severity(score)
    for adp in containers.get("adp", []):
        for metric in adp.get("metrics", []):
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
                if key in metric:
                    score = metric[key].get("baseScore")
                    sev = metric[key].get("baseSeverity", "").upper()
                    if score is not None:
                        return float(score), sev or classify_severity(score)
    return None, None


def extract_vendor_products(cve):
    """Returns dict: vendor -> deduplicated list of product names."""
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})
    vp = defaultdict(list)
    seen = defaultdict(set)

    for affected in cna.get("affected", []):
        v = affected.get("vendor", "").strip()
        p = affected.get("product", "").strip()
        if v and v.lower() != "n/a":
            if p and p.lower() != "n/a" and p not in seen[v]:
                seen[v].add(p)
                vp[v].append(p)
            elif v not in vp:
                vp[v] = []

    if not vp:
        for adp in containers.get("adp", []):
            for affected in adp.get("affected", []):
                v = affected.get("vendor", "").strip()
                p = affected.get("product", "").strip()
                if v and v.lower() != "n/a":
                    if p and p.lower() != "n/a" and p not in seen[v]:
                        seen[v].add(p)
                        vp[v].append(p)
                    elif v not in vp:
                        vp[v] = []

    return vp


def main():
    today = datetime.now()
    cutoff = today - timedelta(days=CUTOFF_DAYS)
    cutoff_str = cutoff.strftime("%Y-%m-%d")
    cutoff_year = cutoff.year

    daily = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))
    vendor_total = defaultdict(int)
    records = defaultdict(list)
    product_to_idx = {}
    product_list = []

    total_files = 0
    in_range = 0

    for year_name in sorted(os.listdir(CVE_DIR)):
        year_path = CVE_DIR / year_name
        if not year_path.is_dir():
            continue
        try:
            yr = int(year_name)
        except ValueError:
            continue
        if yr < cutoff_year - 1:
            continue

        print(f"Scanning {year_name}...", end=" ", flush=True)
        year_count = 0

        for bucket_dir in sorted(year_path.iterdir()):
            if not bucket_dir.is_dir():
                continue
            for cve_file in bucket_dir.iterdir():
                if not cve_file.name.endswith(".json"):
                    continue
                total_files += 1
                try:
                    with open(cve_file) as f:
                        cve = json.load(f)
                except Exception:
                    continue

                if cve.get("cveMetadata", {}).get("state") != "PUBLISHED":
                    continue

                date_pub = cve.get("cveMetadata", {}).get("datePublished", "")
                if not date_pub or len(date_pub) < 10:
                    continue
                date_str = date_pub[:10]
                if date_str < cutoff_str:
                    continue

                score, severity = extract_cvss(cve)
                if severity is None or severity == "NONE" or severity not in SEV_IDX:
                    continue

                vp = extract_vendor_products(cve)
                if not vp:
                    continue

                in_range += 1
                year_count += 1
                si = SEV_IDX[severity]
                cve_id = cve.get("cveMetadata", {}).get("cveId", "")

                for vendor, products in vp.items():
                    daily[vendor][date_str][si] += 1
                    vendor_total[vendor] += 1

                    MAX_PRODS = 10
                    prod_idxs = []
                    for p in products[:MAX_PRODS]:
                        if p not in product_to_idx:
                            product_to_idx[p] = len(product_list)
                            product_list.append(p)
                        prod_idxs.append(product_to_idx[p])
                    extra = max(0, len(products) - MAX_PRODS)

                    # [cveId, dateStr, [productIdxs], sevIdx, score]
                    # extra appended only when products were truncated
                    rec = [cve_id, date_str, prod_idxs, si, round(score, 1)]
                    if extra > 0:
                        rec.append(extra)
                    records[vendor].append(rec)

        print(f"{year_count} in range", flush=True)

    sorted_vendors = sorted(vendor_total.items(), key=lambda x: -x[1])
    all_dates = [d for v in daily.values() for d in v.keys()]
    latest_date = max(all_dates) if all_dates else today.strftime("%Y-%m-%d")
    earliest_date = min(all_dates) if all_dates else cutoff_str

    vendor_idx_map = {}
    for i, (name, _) in enumerate(sorted_vendors):
        vendor_idx_map[name] = i

    output = {
        "meta": {
            "totalFiles": total_files,
            "inRange": in_range,
            "cutoffDate": cutoff_str,
            "earliestDate": earliest_date,
            "latestDate": latest_date,
            "vendorCount": len(sorted_vendors),
        },
        "vendors": [[name, count] for name, count in sorted_vendors],
        "products": product_list,
        "daily": {},
        "records": {},
    }

    for vendor, _ in sorted_vendors:
        vi = vendor_idx_map[vendor]
        entries = []
        for date_str in sorted(daily[vendor].keys()):
            d = daily[vendor][date_str]
            entries.append([date_str, d[0], d[1], d[2], d[3]])
        output["daily"][str(vi)] = entries

        recs = records[vendor]
        recs.sort(key=lambda r: r[1], reverse=True)
        output["records"][str(vi)] = recs

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, separators=(",", ":"))

    file_size = os.path.getsize(OUTPUT_FILE)
    total_records = sum(len(v) for v in records.values())
    print(f"\nDone! Written to {OUTPUT_FILE}")
    print(f"  Files scanned: {total_files}")
    print(f"  CVEs in range: {in_range}")
    print(f"  Total CVE+vendor records: {total_records}")
    print(f"  Unique vendors: {len(sorted_vendors)}")
    print(f"  Unique products: {len(product_list)}")
    print(f"  Date range: {cutoff_str} to {latest_date}")
    print(f"  File size: {file_size / 1024:.1f} KB ({file_size / 1048576:.1f} MB)")
    print(f"  Top vendors: {', '.join(n for n, _ in sorted_vendors[:5])}")


if __name__ == "__main__":
    main()
