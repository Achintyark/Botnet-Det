import pyshark
import os
import time
from datetime import datetime
import psutil
from capture.scan_wifi import scan_connected_devices

def get_wifi_interface():
    for iface in psutil.net_if_addrs().keys():
        if "wlan" in iface.lower() or "wi-fi" in iface.lower() or "wl" in iface.lower():
            return iface
    raise RuntimeError("No WiFi interface found. Please check your connection.")


def capture_device_traffic(ip, duration=30, output_dir="data/pcap"):
    from capture.capture_traffic import get_wifi_interface

    iface = get_wifi_interface()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/{ip.replace('.', '_')}_{timestamp}.pcap"
    os.makedirs(output_dir, exist_ok=True)

    print(f"[+] Capturing traffic for {ip} on {iface} for {duration} seconds...")
    try:
        capture = pyshark.LiveCapture(interface=iface, bpf_filter=f"host {ip}", output_file=filename)
        capture.sniff(timeout=duration)
        print(f"[✓] Saved to {filename}")
        return filename
    except Exception as e:
        print(f"[!] Failed to capture traffic for {ip}: {e}")
        return None

from scapy.all import IP, TCP, send

def simulate_botnet_traffic(target_ip, duration=10):
    print(f"[🧪] Simulating botnet traffic to {target_ip} for {duration}s...")
    packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
    for _ in range(duration * 10):
        send(packet, verbose=False)


if __name__ == "__main__":
    devices = scan_connected_devices()
    for device in devices:
        ip = device["ip"]
        try:
            capture_device_traffic(ip, duration=30)
        except Exception as e:
            print(f"[!] Skipping {ip}: {e}")
