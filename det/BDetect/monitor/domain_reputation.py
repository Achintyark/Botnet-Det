# import requests,os
# from datetime import datetime

# VT_API_KEY = "36d6f22e1c9ef3f3c060682d86006d94ae0d4f66cbe2697de49722cd50846af0"


# import requests
# import os
# import json
# from datetime import datetime

# # Load API key from config
# CONFIG_PATH = os.path.join("config", "thresholds.json")
# if os.path.exists(CONFIG_PATH):
#     with open(CONFIG_PATH, "r") as f:
#         config = json.load(f)
#     VT_API_KEY = config.get("virustotal_api_key", "")
# else:
#     VT_API_KEY = ""

# domain_cache = {}

# def is_domain_malicious(domain):
#     if not VT_API_KEY:
#         print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
#         return "unknown"

#     url = f"https://www.virustotal.com/api/v3/domains/{domain}"
#     headers = {"x-apikey": VT_API_KEY}

#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             data = response.json()
#             stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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




# =======================================================


# import requests
# import os
# from datetime import datetime

# # ✅ Directly use your VirusTotal API key here
# VT_API_KEY = "36d6f22e1c9ef3f3c060682d86006d94ae0d4f66cbe2697de49722cd50846af0"

# # 🧠 In-memory cache to avoid repeated lookups
# domain_cache = {}

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
#             data = response.json()
#             stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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

# # ----------------- Cached Lookup -----------------
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
   

# ============================= 08-10-25 -============================


# import requests
# import os
# from datetime import datetime

# # ✅ VirusTotal API key
# VT_API_KEY = "36d6f22e1c9ef3f3c060682d86006d94ae0d4f66cbe2697de49722cd50846af0"

# # 🧠 In-memory cache
# domain_cache = {}

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
#             data = response.json()
#             stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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

# # ----------------- Cached Lookup -----------------
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
#         print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
#     except Exception as e:
#         print(f"[❌] Failed to log domain alert: {e}")


import requests
import os
import json
from datetime import datetime

# ----------------- Load Config -----------------
def load_config(path="config/thresholds.json"):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[❌] Failed to load config: {e}")
        return {}

config = load_config()
VT_API_KEY = config.get("virustotal_api_key", "")
LOG_PATH = config.get("domain_log_path", "data/domain_alerts.csv")

# ----------------- In-memory Cache -----------------
domain_cache = {}

# ----------------- Reputation Check -----------------
def is_domain_malicious(domain):
    domain = domain.lower().strip()
    if not VT_API_KEY:
        print(f"[⚠️] No VirusTotal API key found. Skipping check for {domain}")
        return "unknown"

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(f"[🔍] VT stats for {domain}: {stats}")
            if stats.get("malicious", 0) > 0:
                return "malicious"
            elif stats.get("suspicious", 0) > 0:
                return "suspicious"
            elif stats:
                return "clean"
            else:
                return "unknown"
        else:
            print(f"[⚠️] Unexpected VT response for {domain}: {response.status_code}")
            return "unknown"
    except Exception as e:
        print(f"[❌] VirusTotal check failed for {domain}: {e}")
        return "error"

# ----------------- Cached Lookup -----------------
def is_domain_malicious_cached(domain):
    domain = domain.lower().strip()
    if domain in domain_cache:
        print(f"[🧠] Cached verdict for {domain}: {domain_cache[domain]}")
        return domain_cache[domain]
    verdict = is_domain_malicious(domain)
    domain_cache[domain] = verdict
    return verdict

# ----------------- Logging -----------------
def log_domain_alert(domain, ip, verdict):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{timestamp},{domain},{ip},{verdict}\n")
        print(f"[📝] Logged domain: {domain} from {ip} → Verdict: {verdict}")
    except Exception as e:
        print(f"[❌] Failed to log domain alert: {e}")
