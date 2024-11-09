from scapy.all import sniff, Dot11, IP, TCP
import time
authorized_aps = ["10:aa:bb:cc:dd:ee", "20:ff:ee:dd:cc:bb"]
trusted_ips = ["192.168.1.1", "192.168.1.2"]

suspicious_keywords = ["malware", "attack", "unauthorized"]

def detect_rogue_ap(packet):
    if packet.haslayer(Dot11):
        
        if packet.type == 0 and packet.subtype == 8:
            mac_address = packet.addr2  
            if mac_address not in authorized_aps:
                print(f"[ALERT] Rogue Access Point Detected: {mac_address}")
