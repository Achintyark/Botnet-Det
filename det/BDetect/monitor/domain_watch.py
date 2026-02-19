# import re
# from scapy.all import sniff, DNSQR, IP
# from monitor.alert_admin import send_email_alert, show_popup_alert
# from monitor.notify_devices import broadcast_alert

# # Load blocklist
# def load_malicious_domains(path="config/malicious_domains.txt"):
#     with open(path, "r") as f:
#         return set(line.strip().lower() for line in f if line.strip())

# malicious_domains = load_malicious_domains()

# # Check if domain is malicious
# def is_malicious(domain):
#     return domain.lower() in malicious_domains

# # Packet handler
# def monitor_dns(packet):
#     if packet.haslayer(DNSQR):
#         domain = packet[DNSQR].qname.decode().rstrip(".")
#         src_ip = packet[IP].src
#         if is_malicious(domain):
#             alert_msg = f"{src_ip} tried to access malicious domain: {domain}"
#             print(f"[⚠️] {alert_msg}")
#             send_email_alert(src_ip, 99.0)
#             show_popup_alert(src_ip)
#             broadcast_alert(alert_msg)

# # Start sniffing
# def start_domain_monitor(interface="Wi-Fi"):
#     print(f"[🔍] Monitoring DNS traffic on {interface}...")
#     sniff(iface=interface, filter="udp port 53", prn=monitor_dns, store=False)




# from scapy.all import sniff, DNSQR, IP
# from monitor.alert_admin import send_email_alert, show_popup_alert
# from monitor.broadcast_alert import broadcast_alert

# def load_malicious_domains(path="config/malicious_domains.txt"):
#     with open(path, "r") as f:
#         return set(line.strip().lower() for line in f if line.strip())

# malicious_domains = load_malicious_domains()

# def is_malicious(domain):
#     return domain.lower() in malicious_domains

# def monitor_dns(packet):
#     if packet.haslayer(DNSQR) and packet.haslayer(IP):
#         domain = packet[DNSQR].qname.decode().rstrip(".")
#         src_ip = packet[IP].src
#         if is_malicious(domain):
#             alert_msg = f"{src_ip} tried to access malicious domain: {domain}"
#             print(f"[🚨] {alert_msg}")
#             send_email_alert(src_ip, 99.0)
#             show_popup_alert(src_ip)
#             broadcast_alert(alert_msg)

# def start_domain_monitor(interface="Wi-Fi"):
#     print(f"[🔍] Monitoring DNS traffic on {interface}...")
#     sniff(iface=interface, filter="port 53", prn=monitor_dns, store=False)




# import socket
# import logging
# from scapy.all import sniff, DNSQR, IP
# from monitor.alert_admin import send_email_alert, show_popup_alert
# from monitor.broadcast_alert import broadcast_alert

# # --- Logging Setup ---
# logging.basicConfig(filename="broadcast_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# # --- Load Blocklist ---
# def load_malicious_domains(path="config/malicious_domains.txt"):
#     try:
#         with open(path, "r") as f:
#             return set(line.strip().lower() for line in f if line.strip())
#     except Exception as e:
#         logging.error(f"[❌] Failed to load domain list: {e}")
#         return set()

# malicious_domains = load_malicious_domains()

# # --- Domain Check ---
# def is_malicious(domain):
#     return domain.lower() in malicious_domains

# # --- DNS Packet Handler ---
# def monitor_dns(packet):
#     if packet.haslayer(DNSQR) and packet.haslayer(IP):
#         try:
#             domain = packet[DNSQR].qname.decode().rstrip(".")
#             src_ip = packet[IP].src
#             print(f"[🔎] DNS request: {src_ip} → {domain}")

#             if is_malicious(domain):
#                 alert_msg = f"{src_ip} tried to access malicious domain: {domain}"
#                 print(f"[🚨] {alert_msg}")
#                 send_email_alert(src_ip, 99.0)
#                 show_popup_alert(src_ip)
#                 broadcast_alert(alert_msg)
#             print(f"[DNS] {src_ip} → {domain}")

#         except Exception as e:
#             logging.error(f"[!] Error processing packet: {e}")

# # --- Start Monitor ---
# def start_domain_monitor(interface="Wi-Fi"):
#     print(f"[🔍] Monitoring DNS traffic on {interface}...")
#     try:
#         sniff(iface=interface, filter="port 53", prn=monitor_dns, store=False)
#     except Exception as e:
#         logging.error(f"[❌] Failed to start sniffing: {e}")
#         print(f"[❌] Sniffing error: {e}")




# import socket
# import logging
# from scapy.all import sniff, DNSQR, IP, get_if_list
# from monitor.alert_admin import send_email_alert, show_popup_alert
# from monitor.broadcast_alert import broadcast_alert

# # --- Logging Setup ---
# logging.basicConfig(filename="broadcast_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# # --- Load Blocklist ---
# def load_malicious_domains(path="config/malicious_domains.txt"):
#     try:
#         with open(path, "r") as f:
#             return set(line.strip().lower() for line in f if line.strip())
#     except Exception as e:
#         logging.error(f"[❌] Failed to load domain list: {e}")
#         return set()

# malicious_domains = load_malicious_domains()

# # --- Domain Check ---
# def is_malicious(domain):
#     return domain.lower() in malicious_domains

# # --- DNS Packet Handler ---
# def monitor_dns(packet):
#     if packet.haslayer(DNSQR) and packet.haslayer(IP):
#         try:
#             domain = packet[DNSQR].qname.decode().rstrip(".")
#             src_ip = packet[IP].src
#             print(f"[🔎] DNS request: {src_ip} → {domain}")

#             if is_malicious(domain):
#                 alert_msg = f"{src_ip} tried to access malicious domain: {domain}"
#                 print(f"[🚨] {alert_msg}")
#                 send_email_alert(src_ip, 99.0)
#                 show_popup_alert(src_ip)
#                 broadcast_alert(alert_msg)

#             logging.info(f"[DNS] {src_ip} → {domain}")

#         except Exception as e:
#             logging.error(f"[!] Error processing packet: {e}")

# # --- Start Monitor ---
# def start_domain_monitor(interface=None):
#     if not interface:
#         interfaces = get_if_list()
#         print("[🧪] Available interfaces:", interfaces)
#         for i in interfaces:
#             if "Wi-Fi" in i or "Ethernet" in i or "Realtek" in i:
#                 interface = i
#                 break
#         if not interface:
#             print("[❌] No valid interface found. DNS monitoring disabled.")
#             return

#     print(f"[🔍] Monitoring DNS traffic on {interface}...")
#     try:
#         sniff(iface=interface, filter="port 53", prn=monitor_dns, store=False)
#     except Exception as e:
#         logging.error(f"[❌] Failed to start sniffing: {e}")
#         print(f"[❌] Sniffing error: {e}")



# ================================================================================================================= #
# ================================================================================================================= #
# ================================================================================================================= #
# ================================================================================================================= #
# ================================================================================================================= #

# from scapy.all import sniff, DNSQR
# import socket
# import time
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert

# def load_malicious_domains(path="config/malicious_domains.txt"):
#     with open(path, "r") as f:
#         return set(line.strip().lower() for line in f if line.strip())

# # def start_domain_monitor():
# #     malicious = load_malicious_domains()
# #     print(f"[🧠] Loaded {len(malicious)} malicious domains.")

# #     while True:
# #         # Replace this with actual domain access detection logic
# #         accessed_domain = simulate_domain_access()

# #         if accessed_domain.lower() in malicious:
# #             print(f"[🚨] Malicious domain accessed: {accessed_domain}")
# #             alert = f"⚠ Accessed malicious domain: {accessed_domain}"
# #             broadcast_alert(alert)
# #             show_popup_alert("🚨 Malicious Website Access", alert)
# #             # Optionally: block or close browser here

# #         time.sleep(5)

# def start_domain_monitor():
#     malicious_domains = load_malicious_domains()
#     print(f"[🌐] Domain monitor started with {len(malicious_domains)} entries.")

#     def process_packet(packet):
#         if packet.haslayer(DNSQR):
#             domain = packet[DNSQR].qname.decode().strip(".").lower()
#             if domain in malicious_domains:
#                 alert = f"⚠ Malicious domain accessed: {domain}. Please close it immediately."
#                 print(f"[🚨] {alert}")
#                 broadcast_alert(alert)
#                 show_popup_alert("🚨 Malicious Website Access", alert)

#     sniff(filter="udp port 53", prn=process_packet, store=0)




# from scapy.all import sniff, TCP, Raw, IP,DNSQR
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert
# from monitor.domain_reputation import is_domain_malicious_cached, log_domain_alert
# import re

# def load_malicious_domains(path="config/malicious_domains.txt"):
#     with open(path, "r") as f:
#         return set(line.strip().lower() for line in f if line.strip())

# def start_domain_monitor():
#     print(f"[🌐] Domain monitor started with live reputation checks.")

#     def process_packet(packet):
#         try:
#             if packet.haslayer(DNSQR):
#                 domain = packet[DNSQR].qname.decode().strip(".").lower()
#                 src_ip = packet[IP].src
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if verdict in ["malicious", "suspicious"]:
#                     alert = f"⚠ {verdict.capitalize()} domain accessed: {domain} by {src_ip}. Please close it immediately."
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#             elif packet.haslayer(Raw) and packet.haslayer(TCP):
#                 payload = packet[Raw].load.decode(errors="ignore").lower()
#                 src_ip = packet[IP].src
#                 domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", payload)
#                 for domain in domains:
#                     domain = domain.lower()
#                     verdict = is_domain_malicious_cached(domain)
#                     log_domain_alert(domain, src_ip, verdict)
#                     if verdict in ["malicious", "suspicious"]:
#                             alert = f"⚠ {verdict.capitalize()} domain accessed: {domain} by {src_ip}. Please close it immediately."
#                             broadcast_alert(alert)
#                             show_popup_alert("🚨 Malicious Website Access", alert)
                        
#                             verdict = is_domain_malicious_cached(domain)
#                             log_domain_alert(domain, src_ip, verdict)

#                             if verdict in ["malicious", "suspicious"]:
#                                 alert = f"⚠ {verdict.capitalize()} domain accessed: {domain} by {src_ip}. Please close it immediately."
#                                 broadcast_alert(alert)
#                                 show_popup_alert("🚨 Malicious Website Access", alert)
#         except Exception as e:
#             print(f"[!] Packet processing error: {e}")

#     sniff(filter="udp port 53 or tcp port 80 or tcp port 443", prn=process_packet, store=0)


# from scapy.all import sniff, TCP, Raw, IP, DNSQR
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert
# from monitor.domain_reputation import is_domain_malicious_cached, log_domain_alert
# import re
# import time

# # Optional: cooldown to suppress repeated alerts
# last_alert = {}

# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         return True
#     return False

# def start_domain_monitor():
#     print(f"[🌐] Domain monitor started with live reputation checks.")

#     def process_packet(packet):
#         try:
#             src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#             # DNS Query Detection
#             if packet.haslayer(DNSQR):
#                 domain = packet[DNSQR].qname.decode().strip(".").lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if verdict in ["malicious", "suspicious"] and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#             # HTTP/HTTPS Payload Inspection
#             elif packet.haslayer(Raw) and packet.haslayer(TCP):
#                 payload = packet[Raw].load.decode(errors="ignore").lower()
#                 src_ip = packet[IP].src

#                 # Focus only on active access lines
#                 active_lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#                 domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(active_lines))

#                 for domain in domains:
#                     domain = domain.lower()
#                     verdict = is_domain_malicious_cached(domain)
#                     log_domain_alert(domain, src_ip, verdict)

#                     if verdict in ["malicious", "suspicious"] and should_alert(domain, src_ip):
#                         alert = (
#                             f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                             f"🌐 Website: {domain}\n"
#                             f"⚠ Action: Please disconnect or investigate immediately."
#                         )
#                         broadcast_alert(alert)
#                         show_popup_alert("🚨 Malicious Website Access", alert)

#         except Exception as e:
#             print(f"[!] Packet processing error: {e}")

#     sniff(filter="udp port 53 or tcp port 80 or tcp port 443", prn=process_packet, store=0)


# ======================================================================================================== 
# ======================================================================================================== 
# ======================================================================================================== 
# ======================================================================================================== 
# ======================================================================================================== 


# from scapy.all import sniff, TCP, Raw, IP, DNSQR
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert
# from monitor.domain_reputation import is_domain_malicious_cached, log_domain_alert
# import re
# import time

# # Optional: fallback blocklist for guaranteed alerts
# FORCE_ALERT_DOMAINS = {"berax30.com", "tw7t79929com-dh.top", "qdsbnx.top"}

# last_alert = {}

# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         return True
#     return False

# def start_domain_monitor():
#     print(f"[🌐] Domain monitor started with live reputation checks.")

#     def process_packet(packet):
#         try:
#             src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#             # DNS Query Detection
#             if packet.haslayer(DNSQR):
#                 domain = packet[DNSQR].qname.decode().strip(".").lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)
#                 print(f"[🔍] {src_ip} → {domain} → Verdict: {verdict}")

#                 if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#             # HTTP/HTTPS Payload Inspection
#             elif packet.haslayer(Raw) and packet.haslayer(TCP):
#                 payload = packet[Raw].load.decode(errors="ignore").lower()
#                 active_lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#                 domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(active_lines))

#                 for domain in domains:
#                     domain = domain.lower()
#                     verdict = is_domain_malicious_cached(domain)
#                     log_domain_alert(domain, src_ip, verdict)
#                     print(f"[🔍] {src_ip} → {domain} → Verdict: {verdict}")

#                     if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                         alert = (
#                             f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                             f"🌐 Website: {domain}\n"
#                             f"⚠ Action: Please disconnect or investigate immediately."
#                         )
#                         broadcast_alert(alert)
#                         show_popup_alert("🚨 Malicious Website Access", alert)

#         except Exception as e:
#             print(f"[!] Packet processing error: {e}")

#     sniff(filter="udp port 53 or tcp port 80 or tcp port 443", prn=process_packet, store=0)




# ====================================================================================================



# import os
# import re
# import time
# import socket
# import requests
# from datetime import datetime
# from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert

# # Load API key from config file
# CONFIG_PATH = os.path.join("config", "thresholds.json")
# if os.path.exists(CONFIG_PATH):
#     import json
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
#     VT_API_KEY = config.get("virustotal_api_key", "")
# else:
#     VT_API_KEY = ""

# # Optional: fallback blocklist
# FORCE_ALERT_DOMAINS = {"berax30.com", "tw7t79929com-dh.top", "qdsbnx.top"}
# domain_cache = {}
# last_alert = {}

# # ----------------- Reputation Check -----------------
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
#         return "unknown"
#     except Exception as e:
#         print(f"[!] VirusTotal check failed for {domain}: {e}")
#         return "error"

# def is_domain_malicious_cached(domain):
#     if domain in domain_cache:
#         return domain_cache[domain]
#     verdict = is_domain_malicious(domain)
#     domain_cache[domain] = verdict
#     return verdict

# # ----------------- Logging -----------------
# def log_domain_alert(domain, ip, verdict):
#     os.makedirs("data", exist_ok=True)
#     log_path = os.path.join("data", "domain_alerts.csv")
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(log_path, "a", encoding="utf-8") as f:
#         f.write(f"{timestamp},{domain},{ip},{verdict}\n")
#         f.flush()
#     print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")

# # ----------------- Alert Suppression -----------------
# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         return True
#     return False

# # ----------------- Packet Handler -----------------
# def process_packet(packet):
#     print(f"[🧪] Packet received at {time.strftime('%H:%M:%S')}")
#     try:
#         src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#         # DNS Query
#         if packet.haslayer(DNSQR):
#             domain = packet[DNSQR].qname.decode().strip(".").lower()
#             verdict = is_domain_malicious_cached(domain)
#             log_domain_alert(domain, src_ip, verdict)

#             if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                 alert = (
#                     f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                     f"🌐 Website: {domain}\n"
#                     f"⚠ Action: Please disconnect or investigate immediately."
#                 )
#                 broadcast_alert(alert)
#                 show_popup_alert("🚨 Malicious Website Access", alert)

#         # HTTP/HTTPS Payload
#         elif packet.haslayer(Raw) and packet.haslayer(TCP):
#             payload = packet[Raw].load.decode(errors="ignore").lower()
#             lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#             domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))

#             for domain in domains:
#                 domain = domain.lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#     except Exception as e:
#         print(f"[!] Packet processing error: {e}")

# # ----------------- Monitor Entry Point -----------------
# def start_domain_monitor():
#     print(f"[🌐] Domain monitor started with live reputation checks.")
#     iface = conf.iface  # Dynamically detect active interface
#     sniff(
#         iface=iface,
#         filter="udp port 53 or tcp port 80 or tcp port 443",
#         prn=process_packet,
#         store=0
#     )



# ================================================================================================================= 

# import os
# import re
# import time
# import socket
# import json
# import requests
# from datetime import datetime
# from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert

# # ----------------- Load API Key -----------------
# CONFIG_PATH = os.path.join("config", "thresholds.json")
# VT_API_KEY = ""
# try:
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
#     VT_API_KEY = config.get("virustotal_api_key", "")
#     if VT_API_KEY:
#         print(f"[🔑] Loaded VirusTotal API key from config.")
#     else:
#         print(f"[⚠️] API key missing in config file.")
# except Exception as e:
#     print(f"[❌] Failed to load config: {e}")

# # ----------------- Globals -----------------
# FORCE_ALERT_DOMAINS = {"berax30.com", "tw7t79929com-dh.top", "qdsbnx.top"}
# domain_cache = {}
# last_alert = {}

# # ----------------- Reputation Check -----------------
# def is_domain_malicious(domain):
#     if not VT_API_KEY:
#         print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
#         return "unknown"

#     url = f"https://www.virustotal.com/api/v3/domains/{domain}"
#     headers = {"x-apikey": VT_API_KEY}

#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             print(f"[🔍] VT stats for {domain}: {stats}")
#             if stats.get("malicious", 0) > 0:
#                 return "malicious"
#             elif stats.get("suspicious", 0) > 0:
#                 return "suspicious"
#             else:
#                 return "clean"
#         else:
#             print(f"[⚠️] Unexpected VT response for {domain}: {response.status_code}")
#             return "unknown"
#     except Exception as e:
#         print(f"[❌] VirusTotal check failed for {domain}: {e}")
#         return "error"

# def is_domain_malicious_cached(domain):
#     if domain in domain_cache:
#         print(f"[🧠] Cached verdict for {domain}: {domain_cache[domain]}")
#         return domain_cache[domain]
#     verdict = is_domain_malicious(domain)
#     domain_cache[domain] = verdict
#     return verdict

# # ----------------- Logging -----------------
# def log_domain_alert(domain, ip, verdict):
#     try:
#         os.makedirs("data", exist_ok=True)
#         log_path = os.path.join("data", "domain_alerts.csv")
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         with open(log_path, "a", encoding="utf-8") as f:
#             f.write(f"{timestamp},{domain},{ip},{verdict}\n")
#             f.flush()
#         print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
#         print(f"[📁] Writing to: {os.path.abspath(log_path)}")
#     except Exception as e:
#         print(f"[❌] Failed to log domain alert: {e}")

# # ----------------- Alert Suppression -----------------
# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         print(f"[🚨] Alert allowed for {domain} from {ip}")
#         return True
#     print(f"[⏳] Alert suppressed for {domain} from {ip}")
#     return False

# # ----------------- Packet Handler -----------------
# def process_packet(packet):
#     print(f"[📦] Packet received at {time.strftime('%H:%M:%S')}")
#     try:
#         src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#         # DNS Query
#         if packet.haslayer(DNSQR):
#             domain = packet[DNSQR].qname.decode().strip(".").lower()
#             print(f"[🌐] DNS Query from {src_ip} → {domain}")
#             verdict = is_domain_malicious_cached(domain)
#             log_domain_alert(domain, src_ip, verdict)

#             if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                 alert = (
#                     f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                     f"🌐 Website: {domain}\n"
#                     f"⚠ Action: Please disconnect or investigate immediately."
#                 )
#                 broadcast_alert(alert)
#                 show_popup_alert("🚨 Malicious Website Access", alert)

#         # HTTP/HTTPS Payload
#         elif packet.haslayer(Raw) and packet.haslayer(TCP):
#             payload = packet[Raw].load.decode(errors="ignore").lower()
#             print(f"[📄] HTTP/HTTPS payload from {src_ip}: {payload[:100]}...")
#             lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#             domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
#             print(f"[🌐] Extracted domains: {domains}")

#             for domain in domains:
#                 domain = domain.lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#     except Exception as e:
#         print(f"[❌] Packet processing error: {e}")

# # ----------------- Monitor Entry Point -----------------
# def start_domain_monitor():
#     print(f"[🧭] Starting domain monitor with live reputation checks...")
#     iface = conf.iface
#     print(f"[🧪] Using interface: {iface}")
#     print(f"[📁] Domain alerts will be logged to: {os.path.abspath('data/domain_alerts.csv')}")
#     try:
#         sniff(
#             iface=iface,
#             filter="udp port 53 or tcp port 80 or tcp port 443",
#             prn=process_packet,
#             store=0
#         )
#     except Exception as e:
#         print(f"[❌] Sniffing failed: {e}")


# ======================== 08-10-25 =========================

# import os
# import re
# import time
# import socket
# import json
# import requests
# from datetime import datetime
# from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert

# # ----------------- Load API Key -----------------
# CONFIG_PATH = os.path.join("config", "thresholds.json")
# VT_API_KEY = ""
# try:
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
#     VT_API_KEY = config.get("virustotal_api_key", "")
#     if VT_API_KEY:
#         print(f"[🔑] Loaded VirusTotal API key from config.")
#     else:
#         print(f"[⚠️] API key missing in config file.")
# except Exception as e:
#     print(f"[❌] Failed to load config: {e}")

# # ----------------- Globals -----------------
# FORCE_ALERT_DOMAINS = {"berax30.com", "tw7t79929com-dh.top", "qdsbnx.top"}
# domain_cache = {}
# last_alert = {}
# benign_ip_log = "data/benign_ips.txt"

# # ----------------- Reputation Check -----------------
# def is_domain_malicious(domain):
#     if not VT_API_KEY:
#         print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
#         return "unknown"

#     url = f"https://www.virustotal.com/api/v3/domains/{domain}"
#     headers = {"x-apikey": VT_API_KEY}

#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             print(f"[🔍] VT stats for {domain}: {stats}")
#             if stats.get("malicious", 0) > 0:
#                 return "malicious"
#             elif stats.get("suspicious", 0) > 0:
#                 return "suspicious"
#             else:
#                 return "clean"
#         else:
#             print(f"[⚠️] Unexpected VT response for {domain}: {response.status_code}")
#             return "unknown"
#     except Exception as e:
#         print(f"[❌] VirusTotal check failed for {domain}: {e}")
#         return "error"

# def is_domain_malicious_cached(domain):
#     if domain in domain_cache:
#         print(f"[🧠] Cached verdict for {domain}: {domain_cache[domain]}")
#         return domain_cache[domain]
#     verdict = is_domain_malicious(domain)
#     domain_cache[domain] = verdict
#     return verdict

# # ----------------- Logging -----------------
# def log_domain_alert(domain, ip, verdict):
#     try:
#         os.makedirs("data", exist_ok=True)
#         log_path = os.path.join("data", "domain_alerts.csv")
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         with open(log_path, "a", encoding="utf-8") as f:
#             f.write(f"{timestamp},{domain},{ip},{verdict}\n")
#             f.flush()
#         print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
#         print(f"[📁] Writing to: {os.path.abspath(log_path)}")
#     except Exception as e:
#         print(f"[❌] Failed to log domain alert: {e}")

# def log_benign_ip(ip):
#     try:
#         if not os.path.exists(benign_ip_log):
#             open(benign_ip_log, "w").close()
#         with open(benign_ip_log, "r") as f:
#             known_ips = set(line.strip() for line in f.readlines())
#         if ip not in known_ips:
#             with open(benign_ip_log, "a") as f:
#                 f.write(f"{ip}\n")
#             print(f"[🟢] Marked {ip} as benign for future boosting.")
#     except Exception as e:
#         print(f"[❌] Failed to log benign IP: {e}")

# # ----------------- Alert Suppression -----------------
# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         print(f"[🚨] Alert allowed for {domain} from {ip}")
#         return True
#     print(f"[⏳] Alert suppressed for {domain} from {ip}")
#     return False

# # ----------------- Packet Handler -----------------
# def process_packet(packet):
#     print(f"[📦] Packet received at {time.strftime('%H:%M:%S')}")
#     try:
#         src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#         # DNS Query
#         if packet.haslayer(DNSQR):
#             domain = packet[DNSQR].qname.decode().strip(".").lower()
#             print(f"[🌐] DNS Query from {src_ip} → {domain}")
#             verdict = is_domain_malicious_cached(domain)
#             log_domain_alert(domain, src_ip, verdict)

#             if verdict == "clean":
#                 log_benign_ip(src_ip)

#             if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                 alert = (
#                     f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                     f"🌐 Website: {domain}\n"
#                     f"⚠ Action: Please disconnect or investigate immediately."
#                 )
#                 broadcast_alert(alert)
#                 show_popup_alert("🚨 Malicious Website Access", alert)

#         # HTTP/HTTPS Payload
#         elif packet.haslayer(Raw) and packet.haslayer(TCP):
#             payload = packet[Raw].load.decode(errors="ignore").lower()
#             print(f"[📄] HTTP/HTTPS payload from {src_ip}: {payload[:100]}...")
#             lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#             domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
#             print(f"[🌐] Extracted domains: {domains}")

#             for domain in domains:
#                 domain = domain.lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if verdict == "clean":
#                     log_benign_ip(src_ip)

#                 if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#     except Exception as e:
#         print(f"[❌] Packet processing error: {e}")

# # ----------------- Monitor Entry Point -----------------
# def start_domain_monitor():
#     print(f"[🧭] Starting domain monitor with live reputation checks...")
#     iface = conf.iface
#     print(f"[🧪] Using interface: {iface}")
#     print(f"[📁] Domain alerts will be logged to: {os.path.abspath('data/domain_alerts.csv')}")
#     try:
#         sniff(
#             iface=iface,
#             filter="udp port 53 or tcp port 80 or tcp port 443",
#             prn=process_packet,
#             store=0
#         )
#     except Exception as e:
#         print(f"[❌] Sniffing failed: {e}")





# ======================== 08-10-25 =========================


# import os
# import re
# import time
# import socket
# import json
# import requests
# from datetime import datetime
# from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf
# from monitor.broadcast_alert import broadcast_alert
# from monitor.alert_admin import show_popup_alert
# from monitor.notify_devices import send_udp_alert  # ✅ NEW

# # ----------------- Load API Key -----------------
# CONFIG_PATH = os.path.join("config", "thresholds.json")
# VT_API_KEY = ""
# try:
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
#     VT_API_KEY = config.get("virustotal_api_key", "")
#     if VT_API_KEY:
#         print(f"[🔑] Loaded VirusTotal API key from config.")
#     else:
#         print(f"[⚠️] API key missing in config file.")
# except Exception as e:
#     print(f"[❌] Failed to load config: {e}")

# # ----------------- Globals -----------------
# FORCE_ALERT_DOMAINS = {"berax30.com", "tw7t79929com-dh.top", "qdsbnx.top"}
# domain_cache = {}
# last_alert = {}
# benign_ip_log = "data/benign_ips.txt"

# # ----------------- Reputation Check -----------------
# def is_domain_malicious(domain):
#     if not VT_API_KEY:
#         print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
#         return "unknown"

#     url = f"https://www.virustotal.com/api/v3/domains/{domain}"
#     headers = {"x-apikey": VT_API_KEY}

#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             print(f"[🔍] VT stats for {domain}: {stats}")
#             if stats.get("malicious", 0) > 0:
#                 return "malicious"
#             elif stats.get("suspicious", 0) > 0:
#                 return "suspicious"
#             else:
#                 return "clean"
#         else:
#             print(f"[⚠️] Unexpected VT response for {domain}: {response.status_code}")
#             return "unknown"
#     except Exception as e:
#         print(f"[❌] VirusTotal check failed for {domain}: {e}")
#         return "error"

# def is_domain_malicious_cached(domain):
#     if domain in domain_cache:
#         print(f"[🧠] Cached verdict for {domain}: {domain_cache[domain]}")
#         return domain_cache[domain]
#     verdict = is_domain_malicious(domain)
#     domain_cache[domain] = verdict
#     return verdict

# # ----------------- Logging -----------------
# def log_domain_alert(domain, ip, verdict):
#     try:
#         os.makedirs("data", exist_ok=True)
#         log_path = os.path.join("data", "domain_alerts.csv")
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         with open(log_path, "a", encoding="utf-8") as f:
#             f.write(f"{timestamp},{domain},{ip},{verdict}\n")
#             f.flush()
#         print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
#         print(f"[📁] Writing to: {os.path.abspath(log_path)}")
#     except Exception as e:
#         print(f"[❌] Failed to log domain alert: {e}")

# def log_benign_ip(ip):
#     try:
#         if not os.path.exists(benign_ip_log):
#             open(benign_ip_log, "w").close()
#         with open(benign_ip_log, "r") as f:
#             known_ips = set(line.strip() for line in f.readlines())
#         if ip not in known_ips:
#             with open(benign_ip_log, "a") as f:
#                 f.write(f"{ip}\n")
#             print(f"[🟢] Marked {ip} as benign for future boosting.")
#     except Exception as e:
#         print(f"[❌] Failed to log benign IP: {e}")

# # ----------------- Alert Suppression -----------------
# def should_alert(domain, ip, cooldown=60):
#     key = f"{domain}_{ip}"
#     now = time.time()
#     if key not in last_alert or now - last_alert[key] > cooldown:
#         last_alert[key] = now
#         print(f"[🚨] Alert allowed for {domain} from {ip}")
#         return True
#     print(f"[⏳] Alert suppressed for {domain} from {ip}")
#     return False

# # ----------------- Packet Handler -----------------
# def process_packet(packet):
#     print(f"[📦] Packet received at {time.strftime('%H:%M:%S')}")
#     try:
#         src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

#         # DNS Query
#         if packet.haslayer(DNSQR):
#             domain = packet[DNSQR].qname.decode().strip(".").lower()
#             print(f"[🌐] DNS Query from {src_ip} → {domain}")
#             verdict = is_domain_malicious_cached(domain)
#             log_domain_alert(domain, src_ip, verdict)

#             if verdict == "clean":
#                 log_benign_ip(src_ip)

#             if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                 alert = (
#                     f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                     f"🌐 Website: {domain}\n"
#                     f"⚠ Action: Please disconnect or investigate immediately."
#                 )
#                 broadcast_alert(alert)  # Main system
#                 send_udp_alert(alert, target_ip=src_ip)  # Specific device
#                 show_popup_alert("🚨 Malicious Website Access", alert)

#         # HTTP/HTTPS Payload
#         elif packet.haslayer(Raw) and packet.haslayer(TCP):
#             payload = packet[Raw].load.decode(errors="ignore").lower()
#             print(f"[📄] HTTP/HTTPS payload from {src_ip}: {payload[:100]}...")
#             lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line or "get " in line or "post " in line]
#             domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
#             print(f"[🌐] Extracted domains: {domains}")

#             for domain in domains:
#                 domain = domain.lower()
#                 verdict = is_domain_malicious_cached(domain)
#                 log_domain_alert(domain, src_ip, verdict)

#                 if verdict == "clean":
#                     log_benign_ip(src_ip)

#                 if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
#                     alert = (
#                         f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
#                         f"🌐 Website: {domain}\n"
#                         f"⚠ Action: Please disconnect or investigate immediately."
#                     )
#                     broadcast_alert(alert)  # Main system
#                     send_udp_alert(alert, target_ip=src_ip)  # Specific device
#                     show_popup_alert("🚨 Malicious Website Access", alert)

#     except Exception as e:
#         print(f"[❌] Packet processing error: {e}")

# # ----------------- Monitor Entry Point -----------------
# def start_domain_monitor():
#     print(f"[🧭] Starting domain monitor with live reputation checks...")
#     iface = conf.iface
#     print(f"[🧪] Using interface: {iface}")
#     print(f"[📁] Domain alerts will be logged to: {os.path.abspath('data/domain_alerts.csv')}")
#     try:
#         sniff(
#             iface=iface,
#             filter="udp port 53 or tcp port 80 or tcp port 443",
#             prn=process_packet,
#             store=0
#         )
#     except Exception as e:
#         print(f"[❌] Sniffing failed: {e}")



import os
import re
import time
import socket
import json
import requests
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf
from monitor.notify_devices import send_udp_alert, show_popup_alert

# ----------------- Load Config -----------------
CONFIG_PATH = os.path.join("config", "thresholds.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"[❌] Failed to load config: {e}")
    config = {}

VT_API_KEY = config.get("virustotal_api_key", "")
ALERT_COOLDOWN = config.get("domain_alert_cooldown", 60)
MAX_ALERTS_PER_DOMAIN = config.get("max_domain_alerts", 2)


from scapy.all import get_if_list, get_if_addr

def get_active_interface():
    local_ip = get_local_ip()
    for iface in get_if_list():
        try:
            if_ip = get_if_addr(iface)
            if if_ip == local_ip:
                return iface
        except Exception:
            continue
    print(f"[⚠️] Could not match IP {local_ip} to any interface. Falling back to default.")
    return conf.iface
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

# ----------------- Dynamic Main System IP -----------------
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"[❌] Failed to get local IP: {e}")
        return None

MAIN_SYSTEM_IP = get_local_ip()

# ----------------- Load Malicious Domains -----------------
MALICIOUS_LIST_PATH = os.path.join("config", "malicious_domains.txt")
FORCE_ALERT_DOMAINS = set()
if os.path.exists(MALICIOUS_LIST_PATH):
    with open(MALICIOUS_LIST_PATH, "r") as f:
        FORCE_ALERT_DOMAINS = set(line.strip().lower() for line in f if line.strip())
else:
    print(f"[⚠️] Malicious domain list not found at {MALICIOUS_LIST_PATH}")

# ----------------- Globals -----------------
domain_cache = {}
last_alert = {}
alert_count = {}
benign_ip_log = "data/benign_ips.txt"

# ----------------- Reputation Check -----------------
def is_domain_malicious(domain):
    if not VT_API_KEY:
        print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
        return "unknown"

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(f"[🔍] VT stats for {domain}: {stats}")
            if stats.get("malicious", 0) > 0:
                return "malicious"
            elif stats.get("suspicious", 0) > 0:
                return "suspicious"
            else:
                return "clean"
        else:
            print(f"[⚠️] Unexpected VT response for {domain}: {response.status_code}")
            return "unknown"
    except Exception as e:
        print(f"[❌] VirusTotal check failed for {domain}: {e}")
        return "error"

def is_domain_malicious_cached(domain):
    if domain in domain_cache:
        print(f"[🧠] Cached verdict for {domain}: {domain_cache[domain]}")
        return domain_cache[domain]
    verdict = is_domain_malicious(domain)
    domain_cache[domain] = verdict
    return verdict

# ----------------- Logging -----------------
def log_domain_alert(domain, ip, verdict):
    try:
        os.makedirs("data", exist_ok=True)
        log_path = os.path.join("data", "domain_alerts.csv")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{timestamp},{domain},{ip},{verdict}\n")
        print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
    except Exception as e:
        print(f"[❌] Failed to log domain alert: {e}")

def log_benign_ip(ip):
    try:
        if not os.path.exists(benign_ip_log):
            open(benign_ip_log, "w").close()
        with open(benign_ip_log, "r") as f:
            known_ips = set(line.strip() for line in f.readlines())
        if ip not in known_ips:
            with open(benign_ip_log, "a") as f:
                f.write(f"{ip}\n")
            print(f"[🟢] Marked {ip} as benign for future boosting.")
    except Exception as e:
        print(f"[❌] Failed to log benign IP: {e}")

# ----------------- Alert Suppression -----------------
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
def detect_file_transfer(payload):
    indicators = [
        "download", "upload", "file=", ".exe", ".zip", ".rar", ".pdf", ".doc", ".xls",
        "multipart/form-data", "get", "post", "put"
    ]
    return any(indicator in payload for indicator in indicators)
from scapy.all import TCP, IP

download_tracker = {}

def is_download_like(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        size = len(packet)
        if size > 1000 and packet[TCP].dport in [80, 443, 8080]:
            now = time.time()
            if ip not in download_tracker or now - download_tracker[ip] > 60:
                download_tracker[ip] = now
                return True
    return False

# ----------------- Packet Handler -----------------
def process_packet(packet):
    try:
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        domains = []

        # --- DNS domain extraction ---
        if packet.haslayer(DNSQR):
            domains.append(packet[DNSQR].qname.decode().strip(".").lower())

        # --- Raw TCP payload inspection ---
        elif packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = packet[Raw].load.decode(errors="ignore").lower()
            botnet_ips = load_botnet_ips()

            # --- File Transfer Detection for Botnet Devices ---
            if src_ip in botnet_ips and detect_file_transfer(payload):
                alert = (
                    f"📁 File Transfer Detected from Botnet Device {src_ip}\n"
                    f"⚠️ Action: Investigate download/upload attempt immediately."
                )
                send_udp_alert(alert, target_ip=src_ip)
                if MAIN_SYSTEM_IP:
                    send_udp_alert(alert, target_ip=MAIN_SYSTEM_IP)
                show_popup_alert("📁 Suspicious File Transfer", alert)

            # --- Domain Extraction from HTTP headers ---
            lines = [line for line in payload.splitlines() if "host:" in line or "referer:" in line]
            found = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", " ".join(lines))
            domains.extend(found)

        # --- Domain Reputation Check ---
        for domain in domains:
            domain = domain.lower()
            verdict = is_domain_malicious_cached(domain)
            log_domain_alert(domain, src_ip, verdict)

            if verdict == "clean":
                log_benign_ip(src_ip)

            if (verdict in ["malicious", "suspicious"] or domain in FORCE_ALERT_DOMAINS) and should_alert(domain, src_ip):
                alert = (
                    f"🚨 Alert: Device {src_ip} accessed a {verdict} domain!\n"
                    f"🌐 Website: {domain}\n"
                    f"⚠ Action: Please disconnect or investigate immediately."
                )
                send_udp_alert(alert, target_ip=src_ip)
                if MAIN_SYSTEM_IP:
                    send_udp_alert(alert, target_ip=MAIN_SYSTEM_IP)
                show_popup_alert("🚨 Malicious Website Access", alert)

        # --- General Download Detection (any device) ---
        if is_download_like(packet):
            alert = (
                f"📡 Download Activity Detected\n"
                f"📱 Device: {src_ip}\n"
                f"⚠️ Action: Investigate internet usage or file transfer."
            )
            send_udp_alert(alert, target_ip=src_ip)
            if MAIN_SYSTEM_IP:
                send_udp_alert(alert, target_ip=MAIN_SYSTEM_IP)
            show_popup_alert("📡 Network Download Alert", alert)

    except Exception as e:
        print(f"[❌] Packet processing error: {e}")

# ----------------- Monitor Entry Point -----------------
def start_domain_monitor():
    print(f"[🧭] Starting domain monitor with live reputation checks...")
    iface = get_active_interface()
    print(f"[🧪] Using interface: {iface}")
    print(f"[📁] Domain alerts will be logged to: {os.path.abspath('data/domain_alerts.csv')}")
    try:
        sniff(
            iface=iface,
            filter="udp port 53 or tcp port 80 or tcp port 443",
            prn=process_packet,
            store=0
        )
    except Exception as e:
        print(f"[❌] Sniffing failed: {e}")
