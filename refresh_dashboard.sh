#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Extracting CVE data..."
python3 extract_daily.py

echo "Injecting data into dashboard..."
python3 -c "
with open('cve_vendor_daily.json') as f:
    data = f.read()
with open('cve_dashboard.html') as f:
    html = f.read()
idx = html.index('const DATA = ') + len('const DATA = ')
nl = html.index('\n', idx)
html = html[:idx] + data + ';' + html[nl:]
with open('cve_dashboard.html', 'w') as f:
    f.write(html)
import os
print(f'Dashboard updated: {os.path.getsize(\"cve_dashboard.html\") / 1048576:.1f} MB')
"

echo "Done."
