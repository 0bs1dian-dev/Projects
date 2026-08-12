import socket
import requests
import time
import argparse

def clean_banner(banner_text):
    """Extracts a cleaned string from the banner for the API query."""
    banner_clean = banner_text.replace("SSH-2.0-", "").replace("_", " ")
    parts = banner_clean.split()
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1].split('p')[0]}"
    return banner_clean

def query_nvd_real(keyword):
    """Queries NIST's National Vulnerability Database (NVD)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 3}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) == 0:
                return None
                
            found_vulnerabilities = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                found_vulnerabilities.append({
                    "id": cve_data.get("id"),
                    "desc": cve_data.get("descriptions", [{}])[0].get("value", "No description available")[:150] + "..."
                })
            return found_vulnerabilities
    except Exception:
        return None
    return None

def scan_and_grab(target_host, port):
    """Checks if the port is open and attempts banner grabbing."""
    result = {"open": False, "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        if s.connect_ex((target_host, port)) == 0:
            result["open"] = True
            try:
                result["banner"] = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                result["banner"] = "Port open (No spontaneous banner)"
    except Exception:
        pass
    finally:
        s.close()
    return result

def generate_markdown_report(target, results):
    """Takes the results and generates a Markdown-formatted report."""
    filename = f"report_{target.replace('.', '_')}.md"
    
    with open(filename, "w") as f:
        f.write(f"# 🛡️ Vulnerability Assessment Report\n\n")
        f.write(f"**Analyzed Target:** `{target}`  \n")
        f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        f.write(f"--- \n\n")
        
        for r in results:
            f.write(f"### 🚪 Port {r['port']} - {r['status']}\n")
            if r['banner']:
                f.write(f"* **Detected Banner:** `{r['banner']}`\n")
            
            if r['cve']:
                f.write(f"\n#### 🚨 Identified Critical Vulnerabilities (NIST NVD):\n")
                for cve in r['cve']:
                    f.write(f"* **{cve['id']}**\n")
                    f.write(f"  * *Description:* {cve['desc']}\n")
            elif r['status'] == "OPEN":
                f.write(f"\n✅ No known CVEs found during initial screening for this release.\n")
            f.write(f"\n\n")
            
    print(f"[*] Report successfully saved to: '{filename}'")

def main():
    # Argparse setup for handling command-line arguments
    parser = argparse.ArgumentParser(description="Real-time Vulnerability Assessment Framework connected to NIST NVD.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or Domain to scan")
    args = parser.parse_args()
    
    # List of standard ports to scan
    common_ports = [21, 22, 80, 443, 8080]
    report_data = []
    
    print(f"[*] Vulnerability Assessment Framework started on: {args.target}")
    print("[*] Live connection to NIST NVD active.\n")
    
    for port in common_ports:
        outcome = scan_and_grab(args.target, port)
        
        if outcome["open"]:
            print(f"[+] Port {port} [OPEN] -> Banner: {outcome['banner']}")
            found_cves = None
            
            # If a banner was retrieved, query NIST
            if "Port open" not in outcome["banner"] and outcome["banner"]:
                keyword = clean_banner(outcome['banner'])
                found_cves = query_nvd_real(keyword)
                
                if found_cves:
                    print(f"    🚨 Found vulnerabilities for '{keyword}'! Generating data...")
            
            # Save data for the final report
            report_data.append({
                "port": port,
                "status": "OPEN",
                "banner": outcome["banner"],
                "cve": found_cves
            })
            
            time.sleep(1) # Respect API rate limits
            
    # Generate report if open ports were discovered
    if report_data:
        print("\n[*] Generating report...")
        generate_markdown_report(args.target, report_data)
    else:
        print("[-] No open ports detected. Report was not generated.")

if __name__ == "__main__":
    main()
