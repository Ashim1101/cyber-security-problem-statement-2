from scapy.all import sniff, Dot11, IP, TCP
import time
authorized_aps = ["10:aa:bb:cc:dd:ee", "20:ff:ee:dd:cc:bb"]
trusted_ips = ["192.168.1.1", "192.168.1.2"]
suspicious_keywords = ["malware", "attack", "unauthorized"]
