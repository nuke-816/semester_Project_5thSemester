import sys, json, pprint
sys.path.insert(0, r'D:\BSCS\Semester 5\Software Engneering\Lab\automated_recon_tool')
from database import insert_scan, get_scan_by_id
from recon_engine import run_recon_scan

scan_id = insert_scan('127.0.0.1')
print('Inserted scan id', scan_id)

# Run the scan (this will call nmap)
run_recon_scan(scan_id, '127.0.0.1')

row = get_scan_by_id(scan_id)
if row:
    data = dict(row)
    try:
        data['raw_results'] = json.loads(data['raw_results'])
    except Exception:
        pass
    pprint.pprint(data)
else:
    print('Scan not found')
