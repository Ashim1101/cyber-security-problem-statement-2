from scapy.all import sniff, Dot11, IP, TCP
import time

# List of authorized Wi-Fi Access Points (replace with known MAC addresses of trusted APs)
authorized_aps = ["10:aa:bb:cc:dd:ee","20:ff:ee:dd:cc:bb"]

# List of known safe IP addresses (add trusted IPs here)
trusted_ips = ["203.0.113.5","192.168.1.5"]

# Keywords to detect suspicious activity in packet payloads (e.g., malware or sensitive data)
suspicious_keywords = ["malware", "attack", "unauthorized"]

# Function to detect rogue Wi-Fi access points
def detect_rogue_ap(packet):
    if packet.haslayer(Dot11):
        # Beacon frames are used by access points to advertise their presence
        if packet.type == 0 and packet.subtype == 8:
            mac_address = packet.addr2  # MAC address of the access point
            if mac_address not in authorized_aps:
                print(f"[ALERT] Rogue Access Point Detected: {mac_address}")

# Function to analyze network traffic
def analyze_network_traffic(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for IPs outside the trusted list
        if src_ip not in trusted_ips and dst_ip not in trusted_ips:
            print(f"[WARNING] Unusual IP Activity Detected from {src_ip} to {dst_ip}")
        
        # Analyze TCP payload for suspicious keywords
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = str(packet[TCP].payload)
            for keyword in suspicious_keywords:
                if keyword in payload:
                    print(f"[ALERT] Suspicious Content Detected in Payload: {payload}")
                    break

# Function to sniff packets and process them
def sniff_packets():
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=0)

# Process each packet by checking for rogue APs and analyzing network traffic
def process_packet(packet):
    # Check for rogue APs
    detect_rogue_ap(packet)
    # Analyze network traffic
    analyze_network_traffic(packet)

# Main code execution
if __name__ == "__main__":
    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("Stopping packet sniffing.")
