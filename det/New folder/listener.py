# import os
# import socket
# import logging
# import time
# from plyer import notification
# import ctypes

# # Setup logging early to ensure capture
# log_path = os.path.join(os.getcwd(), "listener_log.txt")
# logging.basicConfig(
#     filename=log_path,
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# PORT = 9999
# BUFFER_SIZE = 1024

# def show_popup(title, message):
#     try:
#         notification.notify(
#             title=title,
#             message=message,
#             timeout=10
#         )
#         print(f"[🔔] Notification triggered: {title} → {message}")
#         time.sleep(2)  # Ensure OS has time to render popup
#     except Exception as e:
#         print(f"[❌] Plyer failed: {e}. Using fallback popup.")
#         ctypes.windll.user32.MessageBoxW(0, message, title, 1)

# def listen_for_alerts():
#     print(f"[🟢] Listener is starting on UDP port {PORT}...")
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         sock.bind(("", PORT))
#         print(f"[✅] Socket successfully bound to port {PORT}. Waiting for alerts...")
#         logging.info(f"[🟢] Listening for alerts on UDP port {PORT}...")
#     except Exception as e:
#         print(f"[❌] Failed to bind socket: {e}")
#         logging.error(f"Socket bind failed: {e}")
#         return

#     while True:
#         try:
#             print("[⏳] Waiting for broadcast...")
#             data, addr = sock.recvfrom(BUFFER_SIZE)
#             try:
#                 message = data.decode("utf-8", errors="replace")
#             except Exception as e:
#                 message = f"[Decode error] {e}"
#                 logging.error(f"Failed to decode message from {addr[0]}: {e}")

#             print(f"[📥] Alert received from {addr[0]}: {message}")
#             logging.info(f"[📨] Alert received from {addr[0]}: {message}")

#             # Determine alert type
#             if "Botnet detected" in message:
#                 title = "⚠ Botnet Alert"
#             elif "malicious domain" in message or "accessed malicious domain" in message:
#                 title = "🚨 Malicious Website Access"
#             elif "file transfer" in message or "download attempt" in message:
#                 title = "📥 File Transfer Attempt"
#             else:
#                 title = "📢 Network Alert"

#             show_popup(title, message)

#         except Exception as e:
#             print(f"[❌] Error receiving alert: {e}")
#             logging.error(f"[!] Error receiving alert: {e}")

# if _name_ == "_main_":
#     listen_for_alerts()






# ===================== 08-10-25========================

# import os
# import socket
# import logging
# import time
# import ctypes
# import requests
# import threading
# from plyer import notification
# from datetime import datetime

# # --- Config ---
# PORT = 9999
# BUFFER_SIZE = 1024
# VT_API_KEY = "36d6f22e1c9ef3f3c060682d86006d94ae0d4f66cbe2697de49722cd50846af0"
# MALICIOUS_LIST = "malicious_websites.txt"
# LOG_PATH = os.path.join(os.getcwd(), "listener_log.txt")

# # --- Setup Logging ---
# logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s - %(message)s")

# # --- Notification ---
# def show_popup(title, message):
#     try:
#         notification.notify(title=title, message=message, timeout=10)
#         print(f"[🔔] Notification triggered: {title} → {message}")
#         time.sleep(2)
#     except Exception as e:
#         print(f"[❌] Plyer failed: {e}. Using fallback popup.")
#         try:
#             ctypes.windll.user32.MessageBoxW(0, message, title, 1)
#         except Exception as fallback_error:
#             print(f"[❌] Fallback popup failed: {fallback_error}")

# # --- Reputation Check ---
# def is_domain_malicious(domain):
#     if not VT_API_KEY:
#         return "unknown"
#     url = f"https://www.virustotal.com/api/v3/domains/{domain}"
#     headers = {"x-apikey": VT_API_KEY}
#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             if stats.get("malicious", 0) > 0:
#                 return "malicious"
#             elif stats.get("suspicious", 0) > 0:
#                 return "suspicious"
#             else:
#                 return "clean"
#         else:
#             return "unknown"
#     except Exception as e:
#         logging.error(f"[VT Error] {e}")
#         return "error"

# # --- Broadcast Alert to Main System ---
# def send_alert_to_server(message):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(message.encode("utf-8"), ("<broadcast>", PORT))
#         print(f"[📡] Alert broadcasted: {message}")
#     except Exception as e:
#         logging.error(f"[Broadcast Error] {e}")

# # --- Domain Monitor ---
# def monitor_domains():
#     print(f"[🧭] Starting domain monitor...")
#     if not os.path.exists(MALICIOUS_LIST):
#         open(MALICIOUS_LIST, "w").close()

#     with open(MALICIOUS_LIST, "r") as f:
#         known_bad = set(line.strip().lower() for line in f if line.strip())

#     while True:
#         domain = input("Enter domain to test (or 'exit'): ").strip().lower()
#         if domain == "exit":
#             break
#         if not domain:
#             continue

#         verdict = "malicious" if domain in known_bad else is_domain_malicious(domain)
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#         if verdict in ["malicious", "suspicious"]:
#             alert = f"🚨 {timestamp} → Device accessed {verdict} domain: {domain}"
#             logging.warning(alert)
#             show_popup("🚨 Malicious Website Access", alert)
#             send_alert_to_server(alert)
#         else:
#             print(f"[✅] {domain} is clean ({verdict})")

# # --- Listener Entry Point ---
# def listen_for_alerts():
#     print(f"[🟢] Listener is starting on UDP port {PORT}...")
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         sock.bind(("", PORT))
#         print(f"[✅] Bound to port {PORT}. Waiting for alerts...")
#     except Exception as e:
#         logging.error(f"[Bind Error] {e}")
#         return

#     while True:
#         try:
#             data, addr = sock.recvfrom(BUFFER_SIZE)
#             message = data.decode("utf-8", errors="replace")
#             print(f"[📥] Alert received from {addr[0]}: {message}")
#             logging.info(f"[📨] Alert from {addr[0]}: {message}")

#             if "Botnet detected" in message:
#                 title = "⚠ Botnet Alert"
#             elif "malicious domain" in message or "accessed malicious domain" in message:
#                 title = "🚨 Malicious Website Access"
#             elif "file transfer" in message or "download attempt" in message:
#                 title = "📥 File Transfer Attempt"
#             else:
#                 title = "📢 Network Alert"

#             show_popup(title, message)

#         except Exception as e:
#             logging.error(f"[Receive Error] {e}")
# from scapy.all import sniff, DNSQR, IP, TCP, Raw

# def passive_domain_monitor():
#     print("[🌐] Passive domain monitor started...")

#     def process_packet(packet):
#         try:
#             src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#             # DNS Query
#             if packet.haslayer(DNSQR):
#                 domain = packet[DNSQR].qname.decode().strip(".").lower()
#             # HTTP/HTTPS Payload
#             elif packet.haslayer(Raw) and packet.haslayer(TCP):
#                 payload = packet[Raw].load.decode(errors="ignore").lower()
#                 lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line]
#                 domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
#                 domain = domains[0] if domains else None
#             else:
#                 domain = None

#             if domain:
#                 verdict = "malicious" if domain in known_bad else is_domain_malicious(domain)
#                 timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#                 if verdict in ["malicious", "suspicious"]:
#                     alert = f"🚨 {timestamp} → Device accessed {verdict} domain: {domain}"
#                     logging.warning(alert)
#                     show_popup("🚨 Malicious Website Access", alert)
#                     send_alert_to_server(alert)
#                 else:
#                     print(f"[✅] {domain} is clean ({verdict})")

#         except Exception as e:
#             logging.error(f"[Sniff Error] {e}")

#     sniff(filter="udp port 53 or tcp port 80 or tcp port 443", prn=process_packet, store=0)

# # --- Main ---
# if __name__ == "__main__":
#     print("[🚀] Starting listener and passive domain monitor...")

#     if not os.path.exists(MALICIOUS_LIST):
#         open(MALICIOUS_LIST, "w").close()
#     with open(MALICIOUS_LIST, "r") as f:
#         known_bad = set(line.strip().lower() for line in f if line.strip())

#     threading.Thread(target=listen_for_alerts, daemon=True).start()
#     threading.Thread(target=passive_domain_monitor, daemon=True).start()

#     while True:
#         time.sleep(1)




# =============================
# =============================
# =============================
# =============================
# =============================
# =============================


import os
import socket
import logging
import time
import ctypes
import requests
import threading
import re
from datetime import datetime
from plyer import notification
from scapy.all import sniff, DNSQR, IP, TCP, Raw

# ----------------- Config -----------------
VT_API_KEY = "36d6f22e1c9ef3f3c060682d86006d94ae0d4f66cbe2697de49722cd50846af0"  
ALERT_COOLDOWN = 60  # seconds
MAX_ALERTS_PER_DOMAIN = 2
MALICIOUS_LIST_PATH = "malicious_websites.txt"
LOG_PATH = "listener_log.txt"
PORT = 9999
BUFFER_SIZE = 1024

# ----------------- Setup -----------------
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s - %(message)s")

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logging.error(f"Failed to get local IP: {e}")
        return None

MAIN_SYSTEM_IP = get_local_ip()

# ----------------- Domain List -----------------
FORCE_ALERT_DOMAINS = set()
if os.path.exists(MALICIOUS_LIST_PATH):
    with open(MALICIOUS_LIST_PATH, "r") as f:
        FORCE_ALERT_DOMAINS = set(line.strip().lower() for line in f if line.strip())

# ----------------- Notification -----------------
def show_popup(title, message):
    try:
        notification.notify(title=title, message=message, timeout=10)
        print(f"[🔔] Notification triggered: {title} → {message}")
        time.sleep(2)
    except Exception:
        try:
            ctypes.windll.user32.MessageBoxW(0, message, title, 1)
        except Exception as fallback_error:
            logging.error(f"Fallback popup failed: {fallback_error}")

# ----------------- Reputation Check -----------------
domain_cache = {}

def is_domain_malicious(domain):
    if not VT_API_KEY:
        return "unknown"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                return "malicious"
            elif stats.get("suspicious", 0) > 0:
                return "suspicious"
            else:
                return "clean"
        return "unknown"
    except Exception as e:
        logging.error(f"VT Error: {e}")
        return "error"

def is_domain_malicious_cached(domain):
    domain = domain.lower().strip()
    if domain in domain_cache:
        return domain_cache[domain]
    verdict = is_domain_malicious(domain)
    domain_cache[domain] = verdict
    return verdict

# ----------------- Alert Logic -----------------
last_alert = {}
alert_count = {}

def should_alert(domain, ip):
    key = f"{domain}_{ip}"
    now = time.time()
    if key not in last_alert or now - last_alert[key] > ALERT_COOLDOWN:
        last_alert[key] = now
        alert_count[key] = 1
        return True
    if alert_count.get(key, 0) < MAX_ALERTS_PER_DOMAIN:
        alert_count[key] += 1
        return True
    return False

def send_alert_to(ip, message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (ip, PORT))
        print(f"[📡] Alert sent to {ip}: {message}")
    except Exception as e:
        logging.error(f"Send error: {e}")

# ----------------- Passive Domain Monitor -----------------
def passive_domain_monitor():
    print("[🌐] Passive domain monitor started...")

    def process_packet(packet):
        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            domains = []

            if packet.haslayer(DNSQR):
                domains.append(packet[DNSQR].qname.decode().strip(".").lower())
            elif packet.haslayer(Raw) and packet.haslayer(TCP):
                payload = packet[Raw].load.decode(errors="ignore").lower()
                lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line]
                found = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
                domains.extend(found)

            for domain in domains:
                verdict = "malicious" if domain in FORCE_ALERT_DOMAINS else is_domain_malicious_cached(domain)
                if verdict in ["malicious", "suspicious"] and should_alert(domain, src_ip):
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert = f"🚨 {timestamp} → Device accessed {verdict} domain: {domain}"
                    show_popup("🚨 Malicious Website Access", alert)
                    if MAIN_SYSTEM_IP:
                        send_alert_to(MAIN_SYSTEM_IP, alert)
                    send_alert_to(src_ip, alert)
                    logging.warning(alert)

        except Exception as e:
            logging.error(f"Sniff error: {e}")

    sniff(filter="udp port 53 or tcp port 80 or tcp port 443", prn=process_packet, store=0)

# ----------------- Listen for Main System Alerts -----------------
def listen_for_alerts():
    print(f"[🟢] Listening for alerts on port {PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", PORT))
        print(f"[✅] Bound to port {PORT}. Waiting for alerts...")
    except Exception as e:
        logging.error(f"Bind error: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = data.decode("utf-8", errors="replace")
            print(f"[📥] Alert received from {addr[0]}: {message}")
            logging.info(f"Alert from {addr[0]}: {message}")
            show_popup("📢 Network Alert", message)
        except Exception as e:
            logging.error(f"Receive error: {e}")

# ----------------- Main -----------------
if __name__ == "__main__":
    threading.Thread(target=listen_for_alerts, daemon=True).start()
    threading.Thread(target=passive_domain_monitor, daemon=True).start()
    print("[🚀] Listener and domain monitor running in parallel...")
    while True:
        time.sleep(1)
