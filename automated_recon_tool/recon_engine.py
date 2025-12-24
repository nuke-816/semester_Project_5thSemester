import requests
import os
import time
import socket
import subprocess
from database import update_scan_results
from dotenv import load_dotenv

# --- CRITICAL: WATCH FOR THIS MESSAGE IN YOUR TERMINAL ---
print("\n[+] LOADING RECON ENGINE... (If you don't see this, restart the server!)\n")

load_dotenv()

# Load Keys
NMAP_PATH = os.environ.get('NMAP_PATH', 'nmap')
VT_API_KEY = os.environ.get('VT_API_KEY')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')

def _query_nmap(target):
    """Run the locally-installed nmap to enumerate open ports and service/version info.
    Returns a dict: { ip: str, services: [ {port, protocol, state, service, product, version} ] }
    """
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

        # Try to extract IP
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
    if not VT_API_KEY or "YOUR_" in VT_API_KEY: return {"error": "Missing API Key"}
    headers = {"x-apikey": VT_API_KEY}
    type_ = "ip_addresses" if target.replace('.', '').isdigit() else "domains"
    try:
        url = f"https://www.virustotal.com/api/v3/{type_}/{target}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            return {"stats": data.get('last_analysis_stats', {})}
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _query_ipinfo(target):
    query_target = target
    if not target.replace('.', '').isdigit():
        try:
            query_target = socket.gethostbyname(target)
        except:
            return {"error": "Domain Resolution Failed"}

    token = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
    try:
        resp = requests.get(f"https://ipinfo.io/{query_target}/json{token}", timeout=5)
        if resp.status_code == 200: 
            return resp.json()
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def _query_crtsh(target):
    if target.replace('.', '').isdigit(): return {"note": "Skipped (IP target)"}
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    for attempt in range(2):
        try:
            resp = requests.get(f"https://crt.sh/?q={target}&output=json", headers=headers, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        unique = set()
                        interesting = []
                        keywords = ['dev', 'admin', 'test', 'vpn', 'api', 'internal']
                        for entry in data:
                            sub = entry.get('name_value', '').split('\n')[0].lower()
                            if sub not in unique:
                                unique.add(sub)
                                if any(k in sub for k in keywords):
                                    interesting.append(sub)
                        return {"interesting": interesting[:10]}
                except: pass
            elif resp.status_code == 429:
                time.sleep(1)
        except: pass
    return {"note": "No subdomains found."}

def _query_dns_security(target):
    results = {}
    try:
        resp = requests.get(f"https://dns.google/resolve?name={target}&type=TXT", timeout=5)
        if resp.status_code == 200:
            ans = resp.json().get('Answer', [])
            txts = [rec['data'] for rec in ans if rec['type'] == 16]
            results['spf'] = any('v=spf1' in t for t in txts)
            results['dmarc'] = any('v=DMARC1' in t for t in txts)
        return results
    except Exception as e: return {"error": str(e)}

# --- NEW FUNCTIONS ---
def _query_hunter(target):
    if target.replace('.', '').isdigit(): return {"note": "Skipped (IP target)"}
    if not HUNTER_API_KEY or "YOUR_" in HUNTER_API_KEY: 
        return {"error": "Missing Hunter API Key"}
    
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
    if not URLSCAN_API_KEY or "YOUR_" in URLSCAN_API_KEY: 
        return {"error": "Missing UrlScan API Key"}
    try:
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
                    "result_url": latest.get('result')
                }
            return {"note": "No recent scans found."}
        return {"error": f"Status {resp.status_code}"}
    except Exception as e: return {"error": str(e)}

def calculate_impact(results):
    impact = "Low"
    details = []
    
    vt = results.get('virustotal', {})
    if 'error' not in vt and vt.get('stats', {}).get('malicious', 0) > 0:
        impact = "High"
        details.append("Malware detected.")
        
    nmap = results.get('nmap', {})
    if 'error' not in nmap and isinstance(nmap, dict):
        for svc in nmap.get('services', []):
            try:
                port = int(svc.get('port', 0))
            except:
                port = 0
            # Treat common risky ports as higher impact
            if port in [445, 3389]:
                impact = "High"
                details.append(f"Exposed port {port}.")
            elif port in [21, 23]:
                if impact == "Low": impact = "Medium"
                details.append(f"Exposed port {port}.")
        
    hunter = results.get('hunter', {})
    if 'error' not in hunter and hunter.get('emails'):
        if impact == "Low": impact = "Medium"
        details.append("Employee emails exposed.")

    return f"{impact}: {' '.join(details) if details else 'Standard footprint.'}"

def run_recon_scan(scan_id, target):
    print(f"--- STARTING SCAN FOR {target} ---")
    
    # Force keys to exist to prevent HTML errors
    results = {
        "nmap": _query_nmap(target),
        "virustotal": _query_virustotal(target),
        "ipinfo": _query_ipinfo(target),
        "crt_sh": _query_crtsh(target),
        "dns_security": _query_dns_security(target),
        "hunter": _query_hunter(target),
        "urlscan": _query_urlscan(target)
    }

    # DEBUG: Confirm data is generated
    print(f"Hunter Data: {results.get('hunter')}")
    print(f"UrlScan Data: {results.get('urlscan')}")

    impact = calculate_impact(results)
    update_scan_results(scan_id, results, impact)
    print(f"--- SCAN FINISHED ---")