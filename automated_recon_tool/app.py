import requests
import os
import time
import socket
import subprocess
import sqlite3
import json
from database import update_scan_results, insert_scan, get_scan_by_id
from flask import Response, Flask, request, jsonify, render_template
from dotenv import load_dotenv

load_dotenv()

# Load all API keys
NMAP_PATH = os.environ.get('NMAP_PATH', 'nmap')
VT_API_KEY = os.environ.get('VT_API_KEY')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY')   # NEW
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY') # NEW

def _query_nmap(target):
    """Run local nmap to enumerate services and versions."""
    try:
        query_target = target
        if not target[0].isdigit():
            try:
                query_target = socket.gethostbyname(target)
            except:
                pass

        cmd = [NMAP_PATH, '-sV', '-Pn', '-T4', '-oX', '-', query_target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0 or not proc.stdout:
            return {"error": f"{NMAP_PATH} failed: {proc.stderr.strip() or proc.returncode}"}

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(proc.stdout)
        except Exception as e:
            return {"error": f"nmap XML parse error: {str(e)}"}

        ip = None
        host = root.find('host')
        if host is not None:
            addr = host.find('address')
            if addr is not None:
                ip = addr.attrib.get('addr')

        services = []
        for p in root.findall('.//port'):
            try:
                portid = int(p.attrib.get('portid', 0))
            except:
                portid = 0
            proto = p.attrib.get('protocol', '')
            state_el = p.find('state')
            state = state_el.attrib.get('state', 'unknown') if state_el is not None else 'unknown'
            service_el = p.find('service')
            product = service_el.attrib.get('product') if service_el is not None else None
            name = service_el.attrib.get('name') if service_el is not None else None
            version = service_el.attrib.get('version') if service_el is not None else None
            services.append({
                "port": portid,
                "protocol": proto,
                "state": state,
                "service": name or product or 'unknown',
                "product": product or name or 'Unknown',
                "version": version or 'Unknown'
            })

        return {"ip": ip, "services": services}
    except FileNotFoundError:
        return {"error": f"{NMAP_PATH} not found (install nmap or set NMAP_PATH to the full executable)."}
    except Exception as e:
        return {"error": str(e)}

def _query_virustotal(target):
    if not VT_API_KEY or "YOUR_" in VT_API_KEY: return {"error": "Missing/Invalid API Key"}
    headers = {"x-apikey": VT_API_KEY}
    type_ = "ip_addresses" if target.replace('.', '').isdigit() else "domains"
    try:
        url = f"https://www.virustotal.com/api/v3/{type_}/{target}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            return {
                "stats": data.get('last_analysis_stats', {}),
                "votes": data.get('total_votes', {})
            }
        return {"error": f"VT Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _query_ipinfo(target):
    # Resolve Domain to IP first
    query_target = target
    if not target.replace('.', '').isdigit():
        try:
            query_target = socket.gethostbyname(target)
        except:
            return {"error": "Could not resolve domain to IP"}

    token = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
    try:
        resp = requests.get(f"https://ipinfo.io/{query_target}/json{token}", timeout=5)
        if resp.status_code == 200: 
            d = resp.json()
            is_cloud = any(x in d.get('org', '').lower() for x in ['amazon', 'google', 'microsoft', 'digitalocean'])
            return {"loc": d.get('loc'), "org": d.get('org'), "country": d.get('country'), "is_cloud": is_cloud}
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _query_crtsh(target):
    if target.replace('.', '').isdigit(): return {"note": "Skipped (IP target)"}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    for attempt in range(3):
        try:
            resp = requests.get(f"https://crt.sh/?q={target}&output=json", headers=headers, timeout=20)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError: continue
                
                if isinstance(data, list):
                    unique_subs = set()
                    interesting_subs = []
                    keywords = ['dev', 'stg', 'test', 'admin', 'vpn', 'api', 'internal']
                    for entry in data:
                        sub = entry.get('name_value', '').split('\n')[0].lower()
                        if sub not in unique_subs:
                            unique_subs.add(sub)
                            if any(k in sub for k in keywords):
                                interesting_subs.append(sub)
                    return {"total_count": len(unique_subs), "interesting": interesting_subs[:10]}
                return {"note": "No data"}
            elif resp.status_code == 429:
                time.sleep(2)
                continue
        except: pass
    return {"error": "Status 429 (Rate Limit)"}

def _query_dns_security(target):
    results = {}
    try:
        resp_txt = requests.get(f"https://dns.google/resolve?name={target}&type=TXT", timeout=5)
        if resp_txt.status_code == 200:
            ans = resp_txt.json().get('Answer', [])
            txts = [rec['data'] for rec in ans if rec['type'] == 16]
            results['spf'] = any('v=spf1' in t for t in txts)
            results['dmarc'] = any('v=DMARC1' in t for t in txts)
        return results
    except Exception as e: return {"error": str(e)}

# --- NEW APIs ---

def _query_hunter(target):
    """Finds employee emails for social engineering."""
    if target.replace('.', '').isdigit(): return {"note": "Skipped (IP target)"}
    if not HUNTER_API_KEY or "YOUR_" in HUNTER_API_KEY: return {"error": "Missing API Key"}
    
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={HUNTER_API_KEY}&limit=5"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                "emails": [e.get('value') for e in data.get('emails', [])],
                "pattern": data.get('pattern', 'Unknown')
            }
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _query_urlscan(target):
    """Analyzes site behavior."""
    if not URLSCAN_API_KEY or "YOUR_" in URLSCAN_API_KEY: return {"error": "Missing API Key"}
    
    try:
        # Search for existing scans to avoid triggering new ones (faster/free-er)
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
        headers = {'API-Key': URLSCAN_API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('results', [])
            if results:
                latest = results[0]
                return {
                    "verdict": latest.get('verdict', {}).get('malicious', False),
                    "screenshot": latest.get('screenshot'),
                    "technologies": latest.get('page', {}).get('server'),
                    "country": latest.get('page', {}).get('country')
                }
            return {"note": "No recent scans found"}
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def calculate_impact(results):
    impact = "Low"
    details = []
    
    # Check VT
    vt = results.get('virustotal', {})
    if 'error' not in vt and vt.get('stats', {}).get('malicious', 0) > 0:
        impact = "High"
        details.append("Malware detected.")

    # Check Nmap results
    nmap = results.get('nmap', {})
    if 'error' not in nmap and isinstance(nmap, dict):
        for svc in nmap.get('services', []):
            try:
                port = int(svc.get('port', 0))
            except:
                port = 0
            if port in [445, 3389]:
                impact = "High"
                details.append(f"Exposed port {port}.")
            elif port in [21, 23]:
                if impact == "Low": impact = "Medium"
                details.append(f"Exposed port {port}.")

    # Check Hunter (Phishing Risk)
    hunter = results.get('hunter', {})
    if 'error' not in hunter and hunter.get('emails'):
        if impact == "Low": impact = "Medium"
        details.append(f"Exposed {len(hunter['emails'])} employee emails.")

    return f"{impact}: {' '.join(details) if details else 'Standard footprint.'}"

def run_recon_scan(scan_id, target):
    print(f"Running Enhanced Scan for {target}...")
    time.sleep(1)
    
    results = {
        "nmap": _query_nmap(target),
        "virustotal": _query_virustotal(target),
        "ipinfo": _query_ipinfo(target),
        "crt_sh": _query_crtsh(target),
        "dns_security": _query_dns_security(target),
        "hunter": _query_hunter(target),   # NEW
        "urlscan": _query_urlscan(target)  # NEW
    }
    
    impact = calculate_impact(results)
    update_scan_results(scan_id, results, impact)
    print(f"Scan {scan_id} finished.")


# Helper to read raw Nmap XML from the scans DB (no Flask route here)

def _get_raw_nmap_xml(scan_id):
    conn = sqlite3.connect('recon_scans.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT raw_results FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if not row: return None
    try:
        data = json.loads(row['raw_results'])
    except Exception:
        return None
    return data.get('nmap', {}).get('raw_xml')

# Minimal Flask app wrapper so this folder can be run directly
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/results/<int:scan_id>')
def results(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan:
        scan_data = dict(scan)
        try:
            scan_data['raw_results'] = json.loads(scan['raw_results'])
        except (TypeError, json.JSONDecodeError):
            scan_data['raw_results'] = {}
        return render_template('results.html', scan=scan_data)
    return "Scan not found", 404

import threading

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    if not target: return jsonify({"error": "Target required"}), 400
    scan_id = insert_scan(target)
    thread = threading.Thread(target=run_recon_scan, args=(scan_id, target))
    thread.start()
    return jsonify({"status": "started", "scan_id": scan_id}), 202

@app.route('/api/scans', methods=['GET'])
def get_recent_scans():
    conn = sqlite3.connect('recon_scans.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, date_started, status, impact_summary FROM scans ORDER BY id DESC LIMIT 10")
    scans = []
    for r in cursor.fetchall():
        scans.append({
            "id": r[0],
            "target": r[1],
            "date": r[2][:10] if r[2] else "N/A",
            "status": r[3],
            "impact": r[4] or "Pending..."
        })
    conn.close()
    return jsonify(scans)

@app.route('/api/scan/<int:scan_id>/nmap.xml')
def download_nmap_xml(scan_id):
    raw = _get_raw_nmap_xml(scan_id)
    if not raw:
        return "Nmap XML not available", 404
    return Response(raw, mimetype='application/xml', headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_nmap.xml'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
