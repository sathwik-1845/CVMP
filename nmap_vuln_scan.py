import xml.etree.ElementTree as ET
import requests
import json
from datetime import datetime

# ---------------------------
# OpenCTI Configuration
# ---------------------------
OPENCTI_URL = "http://localhost:8500/graphql"
TOKEN = "3cb21cbf-160e-4f37-9860-a95fba0a5c7d"

# ---------------------------
# Vulnerability Database
# ---------------------------
vuln_db = {
    "445": {
        "risk": "HIGH",
        "description": "SMB exposure - possible ransomware attack",
        "cve": "CVE-2017-0144",
        "mitre": "T1021.002"
    },
    "135": {
        "risk": "MEDIUM",
        "description": "MSRPC exposure - possible remote code execution",
        "cve": "CVE-2021-26414",
        "mitre": "T1021"
    },
    "80": {
        "risk": "MEDIUM",
        "description": "Web server exposure",
        "cve": "N/A",
        "mitre": "T1190"
    },
    "5998": {
        "risk": "MEDIUM",
        "description": "HTTP management interface exposure",
        "cve": "N/A",
        "mitre": "T1190"
    }
}

# ---------------------------
# Save results locally (NEW 🔥)
# ---------------------------
def save_local(ip, port, service, vuln):
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "port": port,
        "service": service,
        "risk": vuln["risk"],
        "description": vuln["description"],
        "cve": vuln["cve"],
        "mitre": vuln["mitre"]
    }

    with open("vuln_results.json", "a") as f:
        f.write(json.dumps(data) + "\n")


# ---------------------------
# Send to OpenCTI
# ---------------------------
def send_to_opencti(ip):

    query = f'''
    mutation {{
      stixCyberObservableAdd(
        type: "IPv4-Addr",
        IPv4Addr: {{
          value: "{ip}"
        }}
      ) {{
        id
      }}
    }}
    '''

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            OPENCTI_URL,
            json={"query": query},
            headers=headers
        )

        print("Status:", response.status_code)
        print("Response:", response.text)

    except Exception as e:
        print("Error sending to OpenCTI:", e)



tree = ET.parse("scan_results.xml")
root = tree.getroot()

print("------ Scan Results ------")

# ---------------------------
# Parse Scan Results
# ---------------------------
for host in root.findall("host"):

    address = host.find("address").get("addr")
    print(f"\nHost: {address}")

    ports = host.find("ports")

    for port in ports.findall("port"):
        port_id = port.get("portid")
        protocol = port.get("protocol")

        state = port.find("state").get("state")

        service = port.find("service")
        service_name = service.get("name")

        print(f"Port: {port_id}/{protocol}")
        print(f"State: {state}")
        print(f"Service: {service_name}")

        # ---------------------------
        # Risk Detection
        # ---------------------------
        if port_id in vuln_db:
            vuln = vuln_db[port_id]

            print(f"⚠ Risk Detected: {vuln['description']} ({vuln['risk']})")
            print(f"   CVE: {vuln['cve']}")
            print(f"   MITRE: {vuln['mitre']}")

            # ✅ Save locally (NEW)
            save_local(address, port_id, service_name, vuln)

            # ✅ Send to OpenCTI
            # send_to_opencti(address, port_id, service_name, vuln)
            send_to_opencti(address)

print("\n✅ Scan processing completed and stored")