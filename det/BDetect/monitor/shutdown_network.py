import os
import subprocess

def get_interfaces():
    result = subprocess.check_output("netsh interface show interface", shell=True, text=True)
    interfaces = []
    for line in result.splitlines():
        if "Enabled" in line or "Disabled" in line:
            parts = line.split()
            if len(parts) >= 4:
                interfaces.append(parts[-1])
    return interfaces

def disable_wifi():
    interfaces = get_interfaces()
    for iface in interfaces:
        if "Wi-Fi" in iface or "Wireless" in iface:
            print(f"[🔌] Disabling Wi-Fi interface: {iface}")
            os.system(f'netsh interface set interface name="{iface}" admin=disable')

def disable_ethernet():
    interfaces = get_interfaces()
    for iface in interfaces:
        if "Ethernet" in iface or "LAN" in iface:
            print(f"[🔌] Disabling Ethernet interface: {iface}")
            os.system(f'netsh interface set interface name="{iface}" admin=disable')
