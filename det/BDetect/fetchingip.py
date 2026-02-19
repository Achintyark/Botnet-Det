# sweep_then_arp.py
# No external pip packages required (uses builtin subprocess)
import subprocess
import platform
import ipaddress
import concurrent.futures
import sys
import re

def get_local_network():
    # Replace this default with your subnet if known.
    return "192.168.1.0/24"

def ping(ip):
    plat = platform.system().lower()
    if "windows" in plat:
        cmd = ["ping", "-n", "1", "-w", "100", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    with subprocess.DEVNULL:
        return subprocess.call(cmd) == 0

def arp_table():
    plat = platform.system().lower()
    if "windows" in plat:
        out = subprocess.check_output(["arp", "-a"], text=True)
    else:
        out = subprocess.check_output(["arp", "-n"], text=True)
    return out

def parse_arp(out):
    entries = []
    # crude regex to capture IP and MAC
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})", line)
        if m:
            ip = m.group(1)
            mac = m.group(2)
            entries.append((ip, mac))
    return entries

def main():
    network = get_local_network()
    net = ipaddress.ip_network(network, strict=False)
    # ping sweep in parallel (faster)
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(ping, net.hosts()))
    # then read arp table
    out = arp_table()
    devices = parse_arp(out)
    for ip, mac in devices:
        print(ip, mac)

if __name__ == "__main__":
    main()
