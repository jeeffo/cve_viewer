#!/usr/bin/env python3
"""Extract daily CVE counts + records by vendor. Caches all CVEs in cvelistV5; only new/modified files are parsed on subsequent runs."""

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CVE_DIR = SCRIPT_DIR / "cvelistV5" / "cves"
OUTPUT_FILE = SCRIPT_DIR / "cve_vendor_daily.json"
CACHE_FILE = SCRIPT_DIR / "cve_cache.json"

CUTOFF_DAYS = 400
WEEKLY_DAYS = 730
MONTHLY_DAYS = 1825
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


def parse_cve_file(cve_file):
    """Parse a single CVE JSON file. Returns extracted entry dict or None."""
    try:
        with open(cve_file) as f:
            cve = json.load(f)
    except Exception:
        return None

    if cve.get("cveMetadata", {}).get("state") != "PUBLISHED":
        return None

    date_pub = cve.get("cveMetadata", {}).get("datePublished", "")
    if not date_pub or len(date_pub) < 10:
        return None
    date_str = date_pub[:10]

    score, severity = extract_cvss(cve)
    if severity is None or severity == "NONE" or severity not in SEV_IDX:
        return None

    vp = extract_vendor_products(cve)
    if not vp:
        return None

    cve_id = cve.get("cveMetadata", {}).get("cveId", "")

    return {
        "cve_id": cve_id,
        "date": date_str,
        "sev_idx": SEV_IDX[severity],
        "score": round(score, 1),
        "vp": dict(vp),
    }


def load_cache():
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, separators=(",", ":"))


def iso_week_key(date_str):
    """Convert YYYY-MM-DD to ISO week key like '2024-W42'."""
    d = datetime.strptime(date_str, "%Y-%m-%d")
    iso = d.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def month_key(date_str):
    """Convert YYYY-MM-DD to month key like '2022-10'."""
    return date_str[:7]


def quarter_key(date_str):
    """Convert YYYY-MM-DD to quarter key like '2021-Q3'."""
    year = date_str[:4]
    month = int(date_str[5:7])
    q = (month - 1) // 3 + 1
    return f"{year}-Q{q}"


def main():
    today = datetime.now()
    cutoff = today - timedelta(days=CUTOFF_DAYS)
    cutoff_str = cutoff.strftime("%Y-%m-%d")
    weekly_cutoff = today - timedelta(days=WEEKLY_DAYS)
    weekly_cutoff_str = weekly_cutoff.strftime("%Y-%m-%d")
    monthly_cutoff = today - timedelta(days=MONTHLY_DAYS)
    monthly_cutoff_str = monthly_cutoff.strftime("%Y-%m-%d")

    cache = load_cache()
    new_cache = {}
    cache_hits = 0
    cache_misses = 0
    total_files = 0

    for year_name in sorted(os.listdir(CVE_DIR)):
        year_path = CVE_DIR / year_name
        if not year_path.is_dir():
            continue
        try:
            int(year_name)
        except ValueError:
            continue

        print(f"Scanning {year_name}...", end=" ", flush=True)
        year_hits = 0
        year_misses = 0

        for bucket_dir in sorted(year_path.iterdir()):
            if not bucket_dir.is_dir():
                continue
            for cve_file in bucket_dir.iterdir():
                if not cve_file.name.endswith(".json"):
                    continue
                total_files += 1
                rel_path = f"{year_name}/{bucket_dir.name}/{cve_file.name}"
                mtime = cve_file.stat().st_mtime

                cached = cache.get(rel_path)
                if cached and cached.get("mtime") == mtime:
                    new_cache[rel_path] = cached
                    year_hits += 1
                    cache_hits += 1
                else:
                    parsed = parse_cve_file(cve_file)
                    if parsed is None:
                        new_cache[rel_path] = {"mtime": mtime, "skip": True}
                    else:
                        new_cache[rel_path] = {"mtime": mtime, **parsed}
                    year_misses += 1
                    cache_misses += 1

        print(f"{year_hits} cached, {year_misses} parsed", flush=True)

    save_cache(new_cache)
    print(f"\nCache: {cache_hits} hits, {cache_misses} parsed, {len(new_cache)} total entries")

    # Partition entries into tiers
    daily_entries = []
    weekly_entries = []
    monthly_entries = []
    quarterly_entries = []

    for entry in new_cache.values():
        if entry.get("skip"):
            continue
        date_str = entry.get("date", "")
        if not date_str:
            continue
        if date_str >= cutoff_str:
            daily_entries.append(entry)
        elif date_str >= weekly_cutoff_str:
            weekly_entries.append(entry)
        elif date_str >= monthly_cutoff_str:
            monthly_entries.append(entry)
        else:
            quarterly_entries.append(entry)

    # Build unified vendor totals across all tiers
    vendor_total = defaultdict(int)
    for entry in daily_entries + weekly_entries + monthly_entries + quarterly_entries:
        for vendor in entry["vp"]:
            vendor_total[vendor] += 1

    sorted_vendors = sorted(vendor_total.items(), key=lambda x: -x[1])
    vendor_idx_map = {name: i for i, (name, _) in enumerate(sorted_vendors)}

    # Aggregate daily tier (same as before)
    daily = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))
    records = defaultdict(list)
    product_to_idx = {}
    product_list = []

    for entry in daily_entries:
        cve_id = entry["cve_id"]
        date_str = entry["date"]
        si = entry["sev_idx"]
        score = entry["score"]

        for vendor, products in entry["vp"].items():
            daily[vendor][date_str][si] += 1

            MAX_PRODS = 10
            prod_idxs = []
            for p in products[:MAX_PRODS]:
                if p not in product_to_idx:
                    product_to_idx[p] = len(product_list)
                    product_list.append(p)
                prod_idxs.append(product_to_idx[p])
            extra = max(0, len(products) - MAX_PRODS)

            rec = [cve_id, date_str, prod_idxs, si, score]
            if extra > 0:
                rec.append(extra)
            records[vendor].append(rec)

    # Aggregate rollup tiers
    def aggregate_rollup(entries_list, key_fn):
        rollup = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0]))
        for entry in entries_list:
            date_str = entry["date"]
            si = entry["sev_idx"]
            bk = key_fn(date_str)
            for vendor in entry["vp"]:
                rollup[vendor][bk][si] += 1
        return rollup

    weekly = aggregate_rollup(weekly_entries, iso_week_key)
    monthly = aggregate_rollup(monthly_entries, month_key)
    quarterly = aggregate_rollup(quarterly_entries, quarter_key)

    # Collect all dates for meta
    all_dates = []
    for entries_list in [daily_entries, weekly_entries, monthly_entries, quarterly_entries]:
        for entry in entries_list:
            all_dates.append(entry["date"])
    latest_date = max(all_dates) if all_dates else today.strftime("%Y-%m-%d")
    earliest_date = min(all_dates) if all_dates else cutoff_str

    # Build output
    in_range = len(daily_entries)
    total_all = in_range + len(weekly_entries) + len(monthly_entries) + len(quarterly_entries)

    output = {
        "meta": {
            "totalFiles": total_files,
            "inRange": in_range,
            "totalCves": total_all,
            "cutoffDate": cutoff_str,
            "weeklyCutoffDate": weekly_cutoff_str,
            "monthlyCutoffDate": monthly_cutoff_str,
            "earliestDate": earliest_date,
            "latestDate": latest_date,
            "vendorCount": len(sorted_vendors),
        },
        "vendors": [[name, count] for name, count in sorted_vendors],
        "products": product_list,
        "daily": {},
        "records": {},
        "weekly": {},
        "monthly": {},
        "quarterly": {},
    }

    def serialize_tier(tier_data, sort_key=None):
        result = {}
        for vendor, _ in sorted_vendors:
            vi = vendor_idx_map[vendor]
            if vendor not in tier_data:
                continue
            entries_out = []
            for bk in sorted(tier_data[vendor].keys()):
                d = tier_data[vendor][bk]
                entries_out.append([bk, d[0], d[1], d[2], d[3]])
            if entries_out:
                result[str(vi)] = entries_out
        return result

    output["daily"] = serialize_tier(daily)
    output["weekly"] = serialize_tier(weekly)
    output["monthly"] = serialize_tier(monthly)
    output["quarterly"] = serialize_tier(quarterly)

    for vendor, _ in sorted_vendors:
        vi = vendor_idx_map[vendor]
        if vendor in records:
            recs = records[vendor]
            recs.sort(key=lambda r: r[1], reverse=True)
            output["records"][str(vi)] = recs

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, separators=(",", ":"))

    file_size = os.path.getsize(OUTPUT_FILE)
    cache_size = os.path.getsize(CACHE_FILE)
    total_records = sum(len(v) for v in records.values())
    print(f"\nDone! Written to {OUTPUT_FILE}")
    print(f"  Files scanned: {total_files}")
    print(f"  CVEs (daily/recent): {in_range}")
    print(f"  CVEs (all tiers): {total_all}")
    print(f"  Weekly rollup entries: {sum(len(v) for v in weekly.values())}")
    print(f"  Monthly rollup entries: {sum(len(v) for v in monthly.values())}")
    print(f"  Quarterly rollup entries: {sum(len(v) for v in quarterly.values())}")
    print(f"  Total CVE+vendor records: {total_records}")
    print(f"  Unique vendors: {len(sorted_vendors)}")
    print(f"  Unique products: {len(product_list)}")
    print(f"  Date range: {earliest_date} to {latest_date}")
    print(f"  Output size: {file_size / 1024:.1f} KB ({file_size / 1048576:.1f} MB)")
    print(f"  Cache size: {cache_size / 1024:.1f} KB ({cache_size / 1048576:.1f} MB)")
    print(f"  Top vendors: {', '.join(n for n, _ in sorted_vendors[:5])}")


if __name__ == "__main__":
    main()
