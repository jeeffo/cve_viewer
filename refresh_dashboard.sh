#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Extracting CVE data..."
python3 extract_daily.py

echo "Done."
