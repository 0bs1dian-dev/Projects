import json
from datetime import datetime
from scapy.all import sniff, IP, TCP

# Global dictionary for Port Scan tracking
connection_history = {}
PORT_SCAN_THRESHOLD = 10

def save_alert_json(alert_type, details):
    """
    Takes alert details, adds a precise timestamp, 
    and writes the event to a JSON file in append mode.
    """
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "HIGH" if alert_type == "PORT_SCAN" else "MEDIUM",
        "alert_type": alert_type,
        "details": details
    }
    
    # Write the alert to file (one line per event, JSON Lines format)
    with open("security_alerts.json", "a") as f:
        f.write(json.dumps(payload) + "\n")

def analyze_packet(packet):
    global connection_history
    
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            dest_port = packet[TCP].dport
            
            # 1. UNSECURE PROTOCOLS RULE
            if dest_port in [80, 21, 23]:
                protocols = {80: "HTTP", 21: "FTP", 23: "Telnet"}
                proto_name = protocols[dest_port]
                
                msg = f"Detected unencrypted {proto_name} traffic to {destination_ip}:{dest_port}"
                print(f"[⚠️ SECURITY ALERT] {msg}")
                
                # Save event to JSON
                save_alert_json("INSECURE_PROTOCOL", {
                    "src_ip": source_ip, 
                    "dst_ip": destination_ip, 
                    "port": dest_port, 
                    "protocol": proto_name
                })

            # 2. PORT SCAN RULE
            if source_ip not in connection_history:
                connection_history[source_ip] = set()
            
            connection_history[source_ip].add(dest_port)
            scanned_ports_count = len(connection_history[source_ip])
            
            if scanned_ports_count > PORT_SCAN_THRESHOLD:
                msg = f"IP {source_ip} scanned {scanned_ports_count} distinct ports."
                print(f"[🚨 CRITICAL ALERT] {msg}")
                
                # Save event to JSON
                save_alert_json("PORT_SCAN", {
                    "attacker_ip": source_ip, 
                    "ports_scanned": scanned_ports_count
                })

def main():
    print("[*] Professional mini-IDS started... Active monitoring.")
    print("[*] Alerts will be saved to 'security_alerts.json'.\n")
    sniff(prn=analyze_packet)

if __name__ == "__main__":
    main()
