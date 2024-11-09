from scapy.all import sniff, Dot11, IP, TCP

authorized_aps = ["10:aa:bb:cc:dd:ee", "20:ff:ee:dd:cc:bb"]


trusted_ips = ["192.168.1.1", "192.168.1.2"]


suspicious_keywords = ["malware", "attack", "unauthorized"]

def detect_rogue_ap(packet):
    if packet.haslayer(Dot11):
        
        if packet.type == 0 and packet.subtype == 8:
            mac_address = packet.addr2  
            if mac_address not in authorized_aps:
                print(f"[ALERT] Rogue Access Point Detected: {mac_address}")
def analyze_network_traffic(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip not in trusted_ips and dst_ip not in trusted_ips:
            print(f"[WARNING] Unusual IP Activity Detected from {src_ip} to {dst_ip}")
        
    
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = str(packet[TCP].payload)
            for keyword in suspicious_keywords:
                if keyword in payload:
                    print(f"[ALERT] Suspicious Content Detected in Payload: {payload}")
                    break

def sniff_packets():
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=0)

def process_packet(packet):
    detect_rogue_ap(packet)
    analyze_network_traffic(packet)
    
if __name__ == "__main__":
    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("Stopping packet sniffing.")

