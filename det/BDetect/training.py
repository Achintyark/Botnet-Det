# # from passlib.context import CryptContext

# # pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # print(pwd_context.hash("admin"))  # example



# # from monitor.broadcast_alert import broadcast_alert
# # broadcast_alert("Botnet detected on 10.225.32.101")
# # import socket
# # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# # sock.sendto(b"Botnet detected on 192.168.1.3", ("192.168.1.185", 9999))  # Replace with listener IP
# # print("Direct alert sent.")

# # import pandas as pd

# # df = pd.read_csv("data/domain_alerts.csv", names=["timestamp", "domain", "ip", "verdict"])
# # print(df.sort_values("timestamp", ascending=False).head(20))





# import os
# import re
# import subprocess
# import pandas as pd
# import streamlit as st
# from datetime import datetime, timedelta
# from streamlit_autorefresh import st_autorefresh
# from manuf import manuf

# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# DOMAIN_LOG = "data/domain_alerts.csv"
# RESET_INTERVAL_MINUTES = 10
# ACTIVE_WINDOW_MINUTES = 5

# # --- Session state ---
# if "last_reset_time" not in st.session_state:
#     st.session_state.last_reset_time = datetime.now()
# if "session_ips" not in st.session_state:
#     st.session_state.session_ips = set()

# # --- Auto-refresh ---
# st_autorefresh(interval=10000, limit=None, key="dashboard_refresh")

# # --- Helpers ---
# def extract_raw_ip(enriched_ip):
#     match = re.match(r"(\d+\.\d+\.\d+\.\d+)", enriched_ip)
#     return match.group(1) if match else enriched_ip

# @st.cache_data(ttl=10)
# def load_data():
#     if not os.path.exists(LOG_FILE):
#         st.warning("Waiting for log file...")
#         st.stop()

#     df = pd.read_csv(LOG_FILE, header=None)
#     df.columns = ["timestamp", "enriched_ip", "confidence", "status"]

#     df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#     df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
#     return df


# @st.cache_data(ttl=10)
# def load_alerts():
#     try:
#         df = pd.read_csv(ALERT_LOG, names=["timestamp", "ip", "type", "message"], encoding="utf-8")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         return df.dropna(subset=["timestamp"])
#     except Exception:
#         return pd.DataFrame(columns=["timestamp", "ip", "type", "message"])

# @st.cache_data(ttl=10)
# def load_domain_alerts():
#     try:
#         df = pd.read_csv(DOMAIN_LOG, names=["timestamp", "domain", "ip", "verdict"])
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         return df.dropna(subset=["timestamp"])
#     except Exception:
#         return pd.DataFrame(columns=["timestamp", "domain", "ip", "verdict"])

# def get_arp_lines():
#     """Fetch live ARP entries from system (not cached for real-time accuracy)."""
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# import platform

# def get_connected_ips_from_arp_realtime():
#     """Get truly live connected IPs (ping reachable ARP entries)."""
#     try:
#         lines = subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return set()

#     ips = set()
#     for line in lines:
#         match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
#         if match:
#             ip = match.group(0)
#             # Ping check (1 packet, short timeout)
#             param = "-n" if platform.system().lower() == "windows" else "-c"
#             ping = subprocess.run(["ping", param, "1", ip],
#                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#             if "TTL=" in ping.stdout or "ttl=" in ping.stdout:
#                 ips.add(ip)
#     return ips


# def identify_device(ip):
#     """Try to identify device vendor from MAC."""
#     for line in get_arp_lines():
#         if ip in line:
#             match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#             if match:
#                 mac = match.group(0).replace("-", ":").lower()
#                 vendor = mac_parser.get_manuf(mac)
#                 return f"🖥️ {vendor or 'Unknown Vendor'}"
#     return "❓ Unknown Device"

# def get_blocked_ips():
#     """Read Windows firewall rules to find blocked IPs."""
#     try:
#         output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#         blocked = []
#         for line in output.splitlines():
#             if "Rule Name:" in line and "Block_" in line:
#                 rule_name = line.split(":")[1].strip()
#                 ip = rule_name.split("_")[-1]
#                 blocked.append(ip)
#         return list(set(blocked))
#     except Exception:
#         return []

# def test_block(ip):
#     """Ping IP to test if blocked."""
#     result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
# show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
# show_domain_alerts = st.sidebar.checkbox("Show Domain Alerts", value=True)
# test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

# alert_df = load_alerts()
# st.sidebar.subheader("📢 Recent Alerts")
# for _, row in alert_df.sort_values("timestamp", ascending=False).head(5).iterrows():
#     st.sidebar.warning(f"{row['timestamp']} → {row['message']}")

# if show_domain_alerts:
#     domain_df = load_domain_alerts()
#     st.sidebar.subheader("🌐 Domain Reputation Alerts")
#     for _, row in domain_df.sort_values("timestamp", ascending=False).head(5).iterrows():
#         verdict_icon = "🟥" if row["verdict"] == "malicious" else "🟨" if row["verdict"] == "suspicious" else "🟩"
#         st.sidebar.warning(f"{verdict_icon} {row['timestamp']} → {row['domain']} ({row['ip']}) → {row['verdict']}")

# # --- Main Dashboard ---
# st.title("🚨 Botnet Detection Dashboard")
# st.markdown("---")

# # Auto-clear log
# if datetime.now() - st.session_state.last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
#     if os.path.exists(LOG_FILE):
#         open(LOG_FILE, "w", encoding="utf-8").close()
#         st.toast(f"🧹 Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
#     st.session_state.last_reset_time = datetime.now()
#     st.session_state.session_ips.clear()

# if not os.path.exists(LOG_FILE):
#     st.warning("Waiting for log file...")
#     st.stop()

# df = load_data()
# df["device_type"] = df["enriched_ip"].map(identify_device)


# # --- Real-time IPs from ARP ---
# arp_ips = get_connected_ips_from_arp_realtime()


# # Filter active log entries for suspicious analysis
# cutoff_time = datetime.now() - timedelta(minutes=ACTIVE_WINDOW_MINUTES)
# active_df = df[df["timestamp"] >= cutoff_time]

# # Merge ARP + Active logs for tracking only real-time connected ones
# active_ips = arp_ips

# # Detect new/disconnected devices (live)
# new_ips = active_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - active_ips

# # --- Key Metrics (Now Real-Time Based on ARP) ---
# st.subheader("📈 Key Metrics")
# suspicious_devices = active_df[active_df["status"] != "benign"]["enriched_ip"].nunique()
# benign_devices = len(active_ips) - suspicious_devices
# avg_confidence = round(active_df["confidence"].mean(), 2) if not active_df.empty else 0

# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Connected (Live)", len(active_ips))
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Benign Devices", benign_devices)

# st.markdown("---")

# # --- Device Confidence Log ---
# col1, col2 = st.columns([2, 1])
# with col1:
#     st.subheader("📋 Device Confidence Log")
#     st.dataframe(
#         df.sort_values("timestamp", ascending=False)[
#             ["timestamp", "enriched_ip", "device_type", "confidence", "status"]
#         ],
#         width='stretch',
#         hide_index=True
#     )

#     if show_chart:
#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot_table(index="timestamp", columns="enriched_ip", values="confidence", aggfunc="mean")
#         st.line_chart(chart_data, width='stretch')

#     if show_domain_alerts and not domain_df.empty:
#         with st.expander("🌐 View Full Domain Alert Log"):
#             st.dataframe(domain_df.sort_values("timestamp", ascending=False), width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("enriched_ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             st.success(f"{ip} connected at `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")

#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             st.warning(f"{ip} disconnected at `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         if blocked_ips:
#             for ip in blocked_ips:
#                 status = "✅ Blocked" if test_blocking and test_block(ip) else "⚠️ Rule exists"
#                 st.error(f"{ip} → {status}")
#         else:
#             st.info("No devices currently blocked.")

# # --- Update session state for next refresh ---
# st.session_state.session_ips = active_ips


# import subprocess
# lines = subprocess.check_output(["arp", "-a"], text=True).splitlines()
# print("ARP Output:")
# for line in lines:
#     print(line)



# import subprocess
# import re
# import socket
# import streamlit as st
# from datetime import datetime

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# def get_arp_lines():
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# def get_connected_ips_from_arp():
#     local_ip = socket.gethostbyname(socket.gethostname())
#     subnet_prefix = ".".join(local_ip.split(".")[:3])
#     ips = set()
#     for line in get_arp_lines():
#         match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
#         if match:
#             ip = match.group(0)
#             if ip.startswith(subnet_prefix) and not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
#                 ips.add(ip)
#     return ips

# # --- Main ---
# st.title("🚨 Botnet Detection Dashboard")
# arp_ips = get_connected_ips_from_arp()
# st.write("Discovered Devices:", list(arp_ips))

# if arp_ips:
#     st.subheader("📋 Connected Devices")
#     st.table([{"IP": ip, "Detected At": datetime.now().strftime("%Y-%m-%d %H:%M:%S")} for ip in arp_ips])
# else:
#     st.warning("No devices detected via ARP.")



import os
import re
import socket
import subprocess
import pandas as pd
import streamlit as st
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh
from manuf import manuf

mac_parser = manuf.MacParser()

# --- Page config ---
st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# --- Constants ---
LOG_FILE = "data/prediction_log.csv"
RESET_INTERVAL_MINUTES = 10

# --- Session state ---
if "last_reset_time" not in st.session_state:
    st.session_state.last_reset_time = datetime.now()
if "session_ips" not in st.session_state:
    st.session_state.session_ips = set()

# --- Auto-refresh ---
st_autorefresh(interval=10000, limit=None, key="dashboard_refresh")

# --- Helpers ---
def extract_raw_ip(enriched_ip):
    match = re.match(r"(\d+\.\d+\.\d+\.\d+)", enriched_ip)
    return match.group(1) if match else enriched_ip

@st.cache_data(ttl=10)
def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])
    df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["ip"] = df["enriched_ip"].map(extract_raw_ip)
    df.dropna(subset=["timestamp"], inplace=True)
    return df

@st.cache_data(ttl=10)
def get_arp_lines():
    try:
        return subprocess.check_output(["arp", "-a"], text=True).splitlines()
    except Exception:
        return []

def refresh_arp_cache(subnet_prefix):
    for i in range(1, 255):
        ip = f"{subnet_prefix}.{i}"
        subprocess.run(["ping", ip, "-n", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_connected_ips_from_arp():
    local_ip = socket.gethostbyname(socket.gethostname())
    subnet_prefix = ".".join(local_ip.split(".")[:3])
    refresh_arp_cache(subnet_prefix)
    ips = set()
    for line in get_arp_lines():
        match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if match:
            ip = match.group(0)
            if ip.startswith(subnet_prefix) and not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255") and ip != "255.255.255.255":
                ips.add(ip)
    return ips

def identify_device(ip):
    for line in get_arp_lines():
        if ip in line:
            match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if match:
                mac = match.group(0).replace("-", ":").lower()
                vendor = mac_parser.get_manuf(mac)
                return f"🖥️ {vendor or 'Unknown Vendor'}"
    return "❓ Unknown Device"

# --- Main Dashboard ---
st.title("🚨 Botnet Detection Dashboard")
st.markdown("---")

# Auto-clear log
if datetime.now() - st.session_state.last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, "w", encoding="utf-8").close()
        st.toast(f"🧹 Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
    st.session_state.last_reset_time = datetime.now()
    st.session_state.session_ips.clear()

df = load_data()
arp_ips = get_connected_ips_from_arp()
log_ips = set(df["ip"].unique())

# Add ARP-only devices
new_rows = []
for ip in arp_ips:
    if ip not in log_ips:
        new_rows.append({
            "timestamp": datetime.now(),
            "enriched_ip": ip,
            "confidence": None,
            "status": "pending",
            "ip": ip,
            "device_type": identify_device(ip)
        })

df_all = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)
df_all["is_connected"] = df_all["ip"].isin(arp_ips)
connected_df = df_all[df_all["is_connected"]]
connected_ips = set(connected_df["ip"].unique())

new_ips = connected_ips - st.session_state.session_ips
disconnected_ips = st.session_state.session_ips - connected_ips
st.session_state.session_ips = connected_ips

# --- Key Metrics ---
st.subheader("📈 Key Metrics")
suspicious_devices = connected_df[connected_df["status"] != "benign"]["ip"].nunique()
benign_devices = connected_df[connected_df["status"] == "benign"]["ip"].nunique()
avg_confidence = round(connected_df["confidence"].mean(), 2) if not connected_df["confidence"].dropna().empty else 0

col1, col2, col3 = st.columns(3)
col1.metric("💻 Total Devices Connected", len(connected_ips))
col2.metric("📊 Average Confidence", avg_confidence)
col3.metric("🟢 Benign Devices", benign_devices)

st.markdown("---")

# --- Device Confidence Log ---
col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("📋 Device Confidence Log")
    st.dataframe(
        df_all.sort_values("timestamp", ascending=False)[
            ["timestamp", "enriched_ip", "device_type", "confidence", "status"]
        ],
        width='stretch',
        hide_index=True
    )

with col2:
    st.subheader("🕒 Device Timeline")
    timeline_data = df_all.groupby("ip")["timestamp"].agg(["min", "max"])
    timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
    timeline_data = timeline_data.rename(columns={"min": "First Seen", "max": "Last Seen", "duration": "Duration"})
    st.dataframe(timeline_data, width='stretch')

    if new_ips:
        st.subheader("🆕 New Devices Connected")
        for ip in new_ips:
            match = df_all[df_all["ip"] == ip]
            enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
            first_seen = match["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
            st.success(f"{enriched} connected at `{first_seen}`")

    if disconnected_ips:
        st.subheader("🔌 Devices Disconnected")
        for ip in disconnected_ips:
            match = df_all[df_all["ip"] == ip]
            enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
            last_seen = match["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
            st.warning(f"{enriched} last seen at `{last_seen}`")

# --- Debug Panel ---
with st.expander("🛠️ Debug Panel"):
    st.write("ARP IPs:", list(arp_ips))
    st.write("Connected IPs:", list(connected_ips))
    st.write("Session-tracked IPs:", list(st.session_state.session_ips))
    st.write("Merged DataFrame shape:", df_all.shape)
    st.dataframe(df_all.head(10))
