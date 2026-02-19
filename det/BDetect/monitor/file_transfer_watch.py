# import re
# from scapy.all import sniff, IP, TCP, Raw
# from datetime import datetime

# # Shared dictionary for dashboard access
# pending_transfers = {}

# # Detect file-related HTTP requests
# def detect_file_transfer(packet):
#     if packet.haslayer(Raw) and packet.haslayer(TCP) and packet.haslayer(IP):
#         try:
#             payload = packet[Raw].load.decode(errors="ignore")
#             ip = packet[IP].src

#             # Match file download/upload patterns
#             if "Content-Type: application" in payload or re.search(r"\.(zip|exe|pdf|docx|mp4|apk)", payload):
#                 uri_match = re.search(r"(GET|POST) (.*?) HTTP", payload)
#                 uri = uri_match.group(2) if uri_match else "unknown"

#                 # Log transfer attempt
#                 pending_transfers[ip] = {
#                     "uri": uri,
#                     "timestamp": datetime.now().isoformat()
#                 }
#                 print(f"[📥] File transfer attempt from {ip}: {uri}")
#         except Exception as e:
#             print(f"[!] Error parsing packet: {e}")

# # Start sniffing on given interface
# def start_file_monitor(interface="Wi-Fi"):
#     print(f"[🔍] Monitoring file transfers on {interface}...")
#     sniff(iface=interface, filter="tcp port 80", prn=detect_file_transfer, store=False)


# ===================================================================================================================== #
# ===================================================================================================================== #
# ===================================================================================================================== #
# ===================================================================================================================== #
# ===================================================================================================================== #




# from scapy.all import sniff, TCP, Raw, IP
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert

# def start_file_monitor():
#     print("[📁] File transfer monitor started.")

#     def process_packet(packet):
#         if packet.haslayer(Raw) and packet.haslayer(TCP):
#             payload = packet[Raw].load.decode(errors="ignore").lower()
#             if "upload" in payload or "download" in payload:
#                 ip = packet[IP].src
#                 alert = f"📥 File transfer attempt detected from {ip}. Please investigate."
#                 print(f"[🚨] {alert}")
#                 broadcast_alert(alert)
#                 show_popup_alert("📥 File Transfer Attempt", alert)

#     sniff(filter="tcp", prn=process_packet, store=0)

# from scapy.all import sniff, TCP, Raw, IP
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert
# from datetime import datetime
# import os
# import re

# # Keywords to detect file-related activity
# def detect_file_transfer(payload):
#     indicators = [
#         "download", "upload", "file=", ".exe", ".zip", ".rar", ".pdf", ".doc", ".xls",
#         "multipart/form-data", "get", "post", "put"
#     ]
#     return any(indicator in payload for indicator in indicators)

# # Log detected file transfer to CSV
# def log_file_transfer(ip, payload):
#     os.makedirs("data", exist_ok=True)
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#     # Extract meaningful summary from payload
#     matches = re.findall(r"(get|post|put).*?(\/[\w\-\.]+\.\w+)", payload)
#     if matches:
#         summary = " | ".join([f"{method.upper()} {path}" for method, path in matches])
#     else:
#         # Fallback: extract common file extensions
#         for ext in [".exe", ".zip", ".pdf", ".doc", ".xls"]:
#             if ext in payload:
#                 summary = f"Detected file type: {ext}"
#                 break
#         else:
#             summary = payload[:100].replace("\n", " ").replace("\r", " ")

#     # Write to log file
#     with open("data/file_transfer_log.csv", "a", encoding="utf-8") as f:
#         f.write(f"{timestamp},{ip},{summary}\n")

# # Start the packet sniffer
# def start_file_transfer_monitor():
#     print("[📁] File transfer monitor started...")

#     def process_packet(packet):
#         try:
#             if packet.haslayer(Raw) and packet.haslayer(TCP) and packet.haslayer(IP):
#                 payload = packet[Raw].load.decode(errors="ignore").lower()
#                 src_ip = packet[IP].src

#                 if detect_file_transfer(payload):
#                     log_file_transfer(src_ip, payload)
#                     alert = (
#                         f"📁 File Transfer Detected from {src_ip}\n"
#                         f"⚠️ Action: Investigate download/upload attempt immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("📁 File Transfer Alert", alert)

#         except Exception as e:
#             print(f"[!] File transfer packet error: {e}")

#     sniff(filter="tcp port 80 or tcp port 443 or tcp port 21", prn=process_packet, store=0)



from scapy.all import sniff, TCP, Raw, IP
from monitor.broadcast_alert import broadcast_alert
from monitor.alert_admin import show_popup_alert
from datetime import datetime
import os
import re


def load_botnet_ips():
    try:
        botnet_ips = set()
        with open("data/prediction_log.csv", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 4 and parts[3].strip().lower() == "botnet":
                    ip = parts[1].split("→")[0].strip()
                    botnet_ips.add(ip)
        return botnet_ips
    except Exception as e:
        print(f"[❌] Failed to load botnet IPs: {e}")
        return set()


# ----------------- Detection Logic -----------------
def detect_file_transfer(payload):
    indicators = [
        "download", "upload", "file=", ".exe", ".zip", ".rar", ".pdf", ".doc", ".xls",
        "multipart/form-data", "get", "post", "put"
    ]
    return any(indicator in payload for indicator in indicators)

# ----------------- Logging -----------------
def log_file_transfer(ip, payload, operation):
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract meaningful summary from payload
    matches = re.findall(r"(get|post|put).*?(\/[\w\-\.]+\.\w+)", payload)
    if matches:
        summary = " | ".join([f"{method.upper()} {path}" for method, path in matches])
    else:
        for ext in [".exe", ".zip", ".pdf", ".doc", ".xls"]:
            if ext in payload:
                summary = f"Detected file type: {ext}"
                break
        else:
            summary = payload[:100].replace("\n", " ").replace("\r", " ")

    # Log to file_transfer_log.csv
    with open("data/file_transfer_log.csv", "a", encoding="utf-8") as f:
        f.write(f"{timestamp},{ip},{summary}\n")

    # Log to streamlit_file_events.csv for UI
    with open("data/streamlit_file_events.csv", "a", encoding="utf-8") as f:
        f.write(f"{timestamp},{ip},{operation},{summary}\n")

# ----------------- Sniffer -----------------
def start_file_transfer_monitor():
    print("[📁] File transfer monitor started...")

    def process_packet(packet):
        try:
            if packet.haslayer(Raw) and packet.haslayer(TCP) and packet.haslayer(IP):
                payload = packet[Raw].load.decode(errors="ignore").lower()
                src_ip = packet[IP].src

                if detect_file_transfer(payload):
                    # Determine operation type
                    if "put" in payload or "upload" in payload:
                        operation = "uploaded"
                    elif "get" in payload or "download" in payload:
                        operation = "downloaded"
                    else:
                        operation = "unknown"

                    log_file_transfer(src_ip, payload, operation)

                    alert = (
                        f"📁 File Transfer Detected from {src_ip}\n"
                        f"📦 Operation: {operation.upper()}\n"
                        f"⚠️ Action: Investigate download/upload attempt immediately."
                    )

                    # Notify main system + specific listener
                    broadcast_alert(alert, target_ip=src_ip)

                    # Show popup only on local device
                    show_popup_alert("📁 File Transfer Alert", alert)

        except Exception as e:
            print(f"[❌] File transfer packet error: {e}")

    sniff(filter="tcp port 80 or tcp port 443 or tcp port 21", prn=process_packet, store=0)
