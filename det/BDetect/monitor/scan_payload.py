from scapy.all import *

def detect_data_leak(pcap_path):
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if Raw in pkt:
            payload = pkt[Raw].load
            if b"password" in payload or b"token" in payload or b"Authorization" in payload:
                return True
    return False
