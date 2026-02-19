# import scapy.all as scapy
# import subprocess
# import os

# def get_local_ip():
#     return scapy.get_if_addr(scapy.conf.iface)

# def get_subnet(ip):
#     return ip.rsplit('.', 1)[0] + ".0/24"

# def refresh_arp_cache(subnet):
#     print("[↻] Refreshing ARP cache...")
#     for i in range(1, 255):
#         ip = subnet.replace("/24", f".{i}")
#         os.system(f"ping -n 1 -w 100 {ip} >nul")

# def arp_scan(subnet):
#     print(f"[🔍] Scanning subnet: {subnet}")
#     arp_request = scapy.ARP(pdst=subnet)
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast / arp_request
#     answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

#     devices = []
#     for element in answered_list:
#         devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
#     return devices

# def fallback_scan():
#     print("[🧩] Fallback scan using system ARP table...")
#     output = subprocess.check_output("arp -a", shell=True).decode()
#     devices = []
#     for line in output.splitlines():
#         if "dynamic" in line:
#             parts = line.split()
#             if len(parts) >= 2:
#                 devices.append({"ip": parts[0], "mac": parts[1]})
#     return devices

# def deduplicate(devices):
#     seen = set()
#     unique = []
#     for d in devices:
#         key = (d["ip"], d["mac"])
#         if key not in seen:
#             unique.append(d)
#             seen.add(key)
#     return unique

# def scan_connected_devices():
#     local_ip = get_local_ip()
#     subnet = get_subnet(local_ip)
#     refresh_arp_cache(subnet)
#     devices = arp_scan(subnet) + fallback_scan()
#     return deduplicate(devices)




# import scapy.all as scapy
# import subprocess
# import os

# def get_local_ip():
#     return scapy.get_if_addr(scapy.conf.iface)

# def get_subnet(ip):
#     return ip.rsplit('.', 1)[0] + ".0/24"

# def refresh_arp_cache(subnet):
#     print("[↻] Refreshing ARP cache...")
#     for i in range(1, 255):
#         ip = subnet.replace("/24", f".{i}")
#         os.system(f"ping -n 1 -w 100 {ip} >nul")

# def arp_scan(subnet):
#     print(f"[🔍] Scanning subnet: {subnet}")
#     arp_request = scapy.ARP(pdst=subnet)
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast / arp_request
#     answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

#     devices = []
#     for element in answered_list:
#         devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
#     return devices

# def fallback_scan():
#     print("[🧩] Fallback scan using system ARP table...")
#     output = subprocess.check_output("arp -a", shell=True).decode()
#     devices = []
#     for line in output.splitlines():
#         if "dynamic" in line:
#             parts = line.split()
#             if len(parts) >= 2:
#                 devices.append({"ip": parts[0], "mac": parts[1]})
#     return devices

# def deduplicate(devices):
#     seen = set()
#     unique = []
#     for d in devices:
#         key = (d["ip"], d["mac"])
#         if key not in seen:
#             unique.append(d)
#             seen.add(key)
#     return unique

# def scan_connected_devices():
#     local_ip = get_local_ip()
#     subnet = get_subnet(local_ip)
#     refresh_arp_cache(subnet)
#     devices = arp_scan(subnet) + fallback_scan()
#     return deduplicate(devices)




import scapy.all as scapy
import subprocess
import os
import requests

def get_local_ip():
    return scapy.get_if_addr(scapy.conf.iface)

def get_subnet(ip):
    return ip.rsplit('.', 1)[0] + ".0/24"

def refresh_arp_cache(subnet):
    print("[↻] Refreshing ARP cache...")
    for i in range(1, 255):
        ip = subnet.replace("/24", f".{i}")
        os.system(f"ping -n 1 -w 100 {ip} >nul")

def arp_scan(subnet):
    print(f"[🔍] Scanning subnet: {subnet}")
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        vendor = lookup_mac_vendor(mac)
        device_type = classify_device_type(vendor)
        devices.append({"ip": ip, "mac": mac, "vendor": vendor, "device_type": device_type})
    return devices

def fallback_scan():
    print("[🧩] Fallback scan using system ARP table...")
    output = subprocess.check_output("arp -a", shell=True).decode()
    devices = []
    for line in output.splitlines():
        if "dynamic" in line:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                vendor = lookup_mac_vendor(mac)
                device_type = classify_device_type(vendor)
                devices.append({"ip": ip, "mac": mac, "vendor": vendor, "device_type": device_type})
    return devices

def lookup_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def classify_device_type(vendor):
    vendor = vendor.lower()
    if any(brand in vendor for brand in ["samsung", "vivo", "oppo", "xiaomi", "oneplus"]):
        return "Phone"
    elif any(brand in vendor for brand in ["hp", "lenovo", "dell", "asus", "acer"]):
        return "Laptop"
    elif "apple" in vendor or "mac" in vendor:
        return "MacBook"
    elif "router" in vendor or "tplink" in vendor or "netgear" in vendor:
        return "Router"
    else:
        return "Unknown"

def deduplicate(devices):
    seen = set()
    unique = []
    for d in devices:
        key = (d["ip"], d["mac"])
        if key not in seen:
            unique.append(d)
            seen.add(key)
    return unique

def scan_connected_devices():
    local_ip = get_local_ip()
    subnet = get_subnet(local_ip)
    refresh_arp_cache(subnet)
    devices = arp_scan(subnet) + fallback_scan()
    return deduplicate(devices)
