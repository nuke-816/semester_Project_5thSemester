import subprocess
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_output):
    """
    Parses Nmap XML output to extract service and vulnerability information.
    """
    services = []
    vulns = []
    os_match = "Unknown"

    try:
        root = ET.fromstring(xml_output)
        
        # Find the host element
        host = root.find('host')
        if host is None:
            return {"error": "No host found in Nmap output"}

        # Get OS information
        os_element = host.find('os')
        if os_element is not None:
            os_match_element = os_element.find('osmatch')
            if os_match_element is not None:
                os_match = os_match_element.get('name', 'Unknown')

        # Get port and service information
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service_element = port.find('service')
                    service = {
                        "port": port.get('portid'),
                        "protocol": port.get('protocol'),
                        "product": "Unknown",
                        "version": "Unknown",
                        "cpe": []
                    }
                    if service_element is not None:
                        service["product"] = service_element.get('product', 'Unknown')
                        service["version"] = service_element.get('version', 'Unknown')
                        cpe_element = service_element.find('cpe')
                        if cpe_element is not None:
                            service["cpe"].append(cpe_element.text)
                    
                    services.append(service)

    except ET.ParseError as e:
        return {"error": f"Failed to parse Nmap XML: {e}"}

    return {
        "os": os_match,
        "services": services,
        "vulns": vulns 
    }

def query_nmap(ip_target):
    """
    Requires an IP address.
    """
    if not ip_target:
        return {"error": "No IP resolved for Nmap"}

    try:
        # Run Nmap with service detection, OS detection, and XML output
        command = ["nmap", "-sV", "-O", "-oX", "-", ip_target]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parse the XML output
        parsed_data = parse_nmap_xml(result.stdout)
        
        # Add the IP to the result
        if "error" not in parsed_data:
            parsed_data["ip"] = ip_target

        return parsed_data

    except FileNotFoundError:
        return {"error": "Nmap command not found. Please ensure Nmap is installed and in your PATH."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nmap scan failed: {e.stderr}"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    # Example usage:
    # Replace with a target IP address for testing
    target_ip = "45.33.32.156"  # scanme.nmap.org
    nmap_results = query_nmap(target_ip)
    print(nmap_results)
