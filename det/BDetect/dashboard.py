# import streamlit as st
# import pandas as pd
# import time

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# def load_data():
#     df = pd.read_csv("data/prediction_log.csv", names=["timestamp", "ip", "confidence", "status"])
#     df["timestamp"] = pd.to_datetime(df["timestamp"])
#     return df

# st.title("📡 Real-Time Botnet Detection")
# placeholder = st.empty()
# known_ips = set()

# while True:
#     df = load_data()
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - known_ips

#     with placeholder.container():
#         st.subheader("📋 Device Confidence Log")
#         st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)

#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data)

#         if new_ips:
#             st.subheader("🆕 New Devices Connected")
#             for ip in new_ips:
#                 st.markdown(f"- **{ip}** just connected")

#     known_ips.update(new_ips)
#     time.sleep(10)



# import streamlit as st
# import pandas as pd
# import time
# import os

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# def load_data():
#     df = pd.read_csv("data/prediction_log.csv", names=["timestamp", "ip", "confidence", "status"])
#     df["timestamp"] = pd.to_datetime(df["timestamp"])
#     return df

# def identify_device(ip):
#     # Placeholder logic — replace with MAC/vendor mapping if available
#     if ip.endswith("143"):
#         return "HP Laptop"
#     elif ip.endswith("187"):
#         return "MacBook"
#     elif ip.endswith("101"):
#         return "Vivo Phone"
#     else:
#         return "Unknown Device"

# def track_connections(df):
#     connection_times = {}
#     disconnection_times = {}
#     active_ips = set()

#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         first_seen = ip_data["timestamp"].iloc[0]
#         last_seen = ip_data["timestamp"].iloc[-1]
#         connection_times[ip] = first_seen
#         disconnection_times[ip] = last_seen
#         active_ips.add(ip)

#     return connection_times, disconnection_times, active_ips

# st.title("📡 Real-Time Botnet Detection")
# placeholder = st.empty()
# known_ips = set()

# while True:
#     if not os.path.exists("data/prediction_log.csv"):
#         time.sleep(10)
#         continue

#     df = load_data()
#     connection_times, disconnection_times, active_ips = track_connections(df)
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - known_ips
#     disconnected_ips = known_ips - latest_ips

#     with placeholder.container():
#         st.subheader("📋 Device Confidence Log")
#         st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)

#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data)

#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data)

#         if new_ips:
#             st.subheader("🆕 New Devices Connected")
#             for ip in new_ips:
#                 device_name = identify_device(ip)
#                 st.markdown(f"- **{ip}** ({device_name}) connected at `{connection_times[ip]}`")

#         if disconnected_ips:
#             st.subheader("🔌 Devices Disconnected")
#             for ip in disconnected_ips:
#                 device_name = identify_device(ip)
#                 st.markdown(f"- **{ip}** ({device_name}) last seen at `{disconnection_times[ip]}`")

#     known_ips.update(latest_ips)
#     time.sleep(10)




# import streamlit as st
# import pandas as pd
# import time
# import os
# from capture.scan_wifi import scan_connected_devices

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# def load_data():
#     df = pd.read_csv("data/prediction_log.csv", names=["timestamp", "ip", "confidence", "status"])
#     df["timestamp"] = pd.to_datetime(df["timestamp"])
#     return df

# def identify_device(ip):
#     # Placeholder logic — replace with MAC/vendor mapping if available
#     if ip.endswith("143"):
#         return "HP Laptop"
#     elif ip.endswith("187"):
#         return "MacBook"
#     elif ip.endswith("101"):
#         return "Vivo Phone"
#     else:
#         return "Unknown Device"

# def track_connections(df):
#     connection_times = {}
#     disconnection_times = {}
#     active_ips = set()

#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         first_seen = ip_data["timestamp"].iloc[0]
#         last_seen = ip_data["timestamp"].iloc[-1]
#         connection_times[ip] = first_seen
#         disconnection_times[ip] = last_seen
#         active_ips.add(ip)

#     return connection_times, disconnection_times, active_ips

# st.title("📡 Real-Time Botnet Detection")
# placeholder = st.empty()
# known_ips = set()

# while True:
#     if not os.path.exists("data/prediction_log.csv"):
#         time.sleep(10)
#         continue

#     df = load_data()

#     # Enrich with vendor and device type
#     device_info = {d["ip"]: d for d in scan_connected_devices()}
#     df["vendor"] = df["ip"].map(lambda ip: device_info.get(ip, {}).get("vendor", "Unknown"))
#     df["device_type"] = df["ip"].map(lambda ip: device_info.get(ip, {}).get("device_type", identify_device(ip)))

#     connection_times, disconnection_times, active_ips = track_connections(df)
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - known_ips
#     disconnected_ips = known_ips - latest_ips

#     with placeholder.container():
#         st.subheader("📋 Device Confidence Log")
#         st.dataframe(df.sort_values("timestamp", ascending=False)[["timestamp", "ip", "vendor", "device_type", "confidence", "status"]], width='stretch'
# )

#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data)

#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#         if new_ips:
#             st.subheader("🆕 New Devices Connected")
#             for ip in new_ips:
#                 device_name = df[df["ip"] == ip]["device_type"].iloc[0]
#                 st.markdown(f"- **{ip}** ({device_name}) connected at `{connection_times[ip]}`")

#         if disconnected_ips:
#             st.subheader("🔌 Devices Disconnected")
#             for ip in disconnected_ips:
#                 device_name = df[df["ip"] == ip]["device_type"].iloc[0]
#                 st.markdown(f"- **{ip}** ({device_name}) last seen at `{disconnection_times[ip]}`")

#     known_ips.update(latest_ips)
#     time.sleep(10)



# import streamlit as st
# import pandas as pd
# import time
# import os
# from datetime import datetime, timedelta
# from capture.scan_wifi import scan_connected_devices

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# LOG_FILE = "data/prediction_log.csv"
# RESET_INTERVAL_MINUTES = 60  # Clear log every hour
# last_reset_time = datetime.now()
# session_ips = set()  # Tracks devices seen in current session

# def load_data():
#     df = pd.read_csv(LOG_FILE, names=["timestamp", "ip", "confidence", "status"])
#     df["timestamp"] = pd.to_datetime(df["timestamp"])
#     return df

# def identify_device(ip):
#     if ip.endswith("143"):
#         return "HP Laptop"
#     elif ip.endswith("187"):
#         return "MacBook"
#     elif ip.endswith("101"):
#         return "Vivo Phone"
#     else:
#         return "Unknown Device"

# def track_connections(df):
#     connection_times = {}
#     disconnection_times = {}
#     active_ips = set()

#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         first_seen = ip_data["timestamp"].iloc[0]
#         last_seen = ip_data["timestamp"].iloc[-1]
#         connection_times[ip] = first_seen
#         disconnection_times[ip] = last_seen
#         active_ips.add(ip)

#     return connection_times, disconnection_times, active_ips

# st.title("📡 Real-Time Botnet Detection")
# placeholder = st.empty()

# while True:
#     # Auto-clear log every hour
#     if datetime.now() - last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
#         if os.path.exists(LOG_FILE):
#             open(LOG_FILE, "w").close()
#             print(f"[🧹] Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
#         last_reset_time = datetime.now()
#         session_ips.clear()  # Reset session tracking

#     if not os.path.exists(LOG_FILE):
#         time.sleep(10)
#         continue

#     df = load_data()

#     # Enrich with vendor and device type
#     device_info = {d["ip"]: d for d in scan_connected_devices()}
#     df["vendor"] = df["ip"].map(lambda ip: device_info.get(ip, {}).get("vendor", "Unknown"))
#     df["device_type"] = df["ip"].map(lambda ip: device_info.get(ip, {}).get("device_type", identify_device(ip)))

#     connection_times, disconnection_times, active_ips = track_connections(df)
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - session_ips
#     disconnected_ips = session_ips - latest_ips

#     with placeholder.container():
#         st.subheader("📋 Device Confidence Log")
#         st.dataframe(
#             df.sort_values("timestamp", ascending=False)[
#                 ["timestamp", "ip", "vendor", "device_type", "confidence", "status"]
#             ],
#             width='stretch'
#         )

#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data)

#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#         if new_ips:
#             st.subheader("🆕 New Devices Connected")
#             for ip in new_ips:
#                 device_name = df[df["ip"] == ip]["device_type"].iloc[0]
#                 st.markdown(f"- **{ip}** ({device_name}) connected at `{connection_times[ip]}`")

#         if disconnected_ips:
#             st.subheader("🔌 Devices Disconnected")
#             for ip in disconnected_ips:
#                 device_name = df[df["ip"] == ip]["device_type"].iloc[0]
#                 st.markdown(f"- **{ip}** ({device_name}) last seen at `{disconnection_times[ip]}`")

#     session_ips.update(latest_ips)
#     time.sleep(10)



# import streamlit as st
# import pandas as pd
# import time
# import os
# import re
# from datetime import datetime, timedelta

# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide")

# LOG_FILE = "data/prediction_log.csv"
# RESET_INTERVAL_MINUTES = 60  # Clear log every hour
# last_reset_time = datetime.now()
# session_ips = set()  # Tracks devices seen in current session

# def extract_raw_ip(enriched_ip):
#     match = re.match(r"(\d+\.\d+\.\d+\.\d+)", enriched_ip)
#     return match.group(1) if match else enriched_ip

# @st.cache_data(ttl=10)
# def load_data():
#     try:
#         df = pd.read_csv(
#             LOG_FILE,
#             names=["timestamp", "enriched_ip", "confidence", "status"],
#             encoding="utf-8",
#             quotechar='"',
#             on_bad_lines="skip"  # skips malformed lines
#         )
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

# def identify_device(ip):
#     if ip.endswith("143"):
#         return "HP Laptop"
#     elif ip.endswith("187"):
#         return "MacBook"
#     elif ip.endswith("101"):
#         return "Vivo Phone"
#     else:
#         return "Unknown Device"

# def track_connections(df):
#     connection_times = {}
#     disconnection_times = {}
#     active_ips = set()

#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         first_seen = ip_data["timestamp"].iloc[0]
#         last_seen = ip_data["timestamp"].iloc[-1]
#         connection_times[ip] = first_seen
#         disconnection_times[ip] = last_seen
#         active_ips.add(ip)

#     return connection_times, disconnection_times, active_ips

# st.title("📡 Real-Time Botnet Detection")
# placeholder = st.empty()

# while True:
#     # Auto-clear log every hour
#     if datetime.now() - last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
#         if os.path.exists(LOG_FILE):
#             open(LOG_FILE, "w", encoding="utf-8").close()
#             print(f"[🧹] Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
#         last_reset_time = datetime.now()
#         session_ips.clear()

#     if not os.path.exists(LOG_FILE):
#         time.sleep(10)
#         continue

#     df = load_data()
#     if df.empty:
#         time.sleep(10)
#         continue

#     df["device_type"] = df["ip"].map(identify_device)

#     connection_times, disconnection_times, active_ips = track_connections(df)
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - session_ips
#     disconnected_ips = session_ips - latest_ips

#     with placeholder.container():
#         st.subheader("📋 Device Confidence Log")
#         st.dataframe(
#             df.sort_values("timestamp", ascending=False)[
#                 ["timestamp", "enriched_ip", 
#                 #  "device_type", 
#                  "confidence", "status"]
#             ],
#         width='stretch'
#         )

#         st.subheader("📈 Confidence Over Time")
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data)

#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#         if new_ips:
#             st.subheader("🆕 New Devices Connected")
#             for ip in new_ips:
#                 enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#                 st.markdown(f"- **{enriched}** connected at `{connection_times[ip]}`")

#         if disconnected_ips:
#             st.subheader("🔌 Devices Disconnected")
#             for ip in disconnected_ips:
#                 enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#                 st.markdown(f"- **{enriched}** last seen at `{disconnection_times[ip]}`")

#     session_ips.update(latest_ips)
#     time.sleep(10)


# import streamlit as st
# import pandas as pd
# import time
# import os
# import re
# from datetime import datetime, timedelta

# # --- Page config ---
# st.set_page_config(
#     page_title="Botnet Detection Dashboard",
#     layout="wide",
#     initial_sidebar_state="expanded",
# )

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# RESET_INTERVAL_MINUTES = 10
# last_reset_time = datetime.now()
# session_ips = set()

# # --- Helpers ---
# def extract_raw_ip(enriched_ip):
#     match = re.match(r"(\d+\.\d+\.\d+\.\d+)", enriched_ip)
#     return match.group(1) if match else enriched_ip


# @st.cache_data(ttl=10)
# def load_data():
#     try:
#         df = pd.read_csv(
#             LOG_FILE,
#             names=["timestamp", "enriched_ip", "confidence", "status"],
#             encoding="utf-8",
#             quotechar='"',
#             on_bad_lines="skip"
#         )
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])


# def identify_device(ip):
#     if ip.endswith("143"):
#         return "💻 HP Laptop"
#     elif ip.endswith("187"):
#         return "🍎 MacBook"
#     elif ip.endswith("101"):
#         return "📱 Vivo Phone"
#     else:
#         return "❓ Unknown Device"


# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips


# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# st.sidebar.markdown("Adjust settings for real-time monitoring.")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)

# # --- Main Dashboard ---
# st.title("🚨 Botnet Detection Dashboard")
# st.markdown("---")

# placeholder = st.empty()

# while True:
#     # Auto-clear log
#     if datetime.now() - last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
#         if os.path.exists(LOG_FILE):
#             open(LOG_FILE, "w", encoding="utf-8").close()
#             st.toast(f"🧹 Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
#         last_reset_time = datetime.now()
#         session_ips.clear()

#     if not os.path.exists(LOG_FILE):
#         time.sleep(refresh_interval)
#         continue

#     df = load_data()
#     if df.empty:
#         time.sleep(refresh_interval)
#         continue

#     df["device_type"] = df["ip"].map(identify_device)
#     connection_times, disconnection_times, active_ips = track_connections(df)
#     latest_ips = set(df["ip"].unique())
#     new_ips = latest_ips - session_ips
#     disconnected_ips = session_ips - latest_ips

#     with placeholder.container():
#         # --- Key Metrics Cards ---
#         st.subheader("📈 Key Metrics")
#         total_devices = len(df["ip"].unique())
#         avg_confidence = round(df["confidence"].mean(), 2) if not df.empty else 0
#         active_devices = len(active_ips)

#         col1, col2, col3 = st.columns(3)
#         col1.metric("💻 Total Devices Detected", total_devices)
#         col2.metric("📊 Average Confidence", avg_confidence)
#         col3.metric("🟢 Active Devices", active_devices)

#         st.markdown("---")

#         # --- Device Logs & Confidence Chart ---
#         col1, col2 = st.columns([2, 1])

#         with col1:
#             st.subheader("📋 Device Confidence Log")
#             st.dataframe(
#                 df.sort_values("timestamp", ascending=False)[
#                     ["timestamp", "enriched_ip", "device_type", "confidence", "status"]
#                 ],
#                 width='stretch',
#                 hide_index=True
#             )

#             if show_chart:
#                 st.subheader("📈 Confidence Over Time")
#                 chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#                 st.line_chart(chart_data, width='stretch')

#         with col2:
#             if show_timeline:
#                 st.subheader("🕒 Device Presence Timeline")
#                 timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#                 timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#                 st.dataframe(timeline_data, width='stretch')

#             if new_ips:
#                 st.subheader("🆕 New Devices Connected")
#                 for ip in new_ips:
#                     enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#                     st.success(f"{enriched} connected at `{connection_times[ip]}`")

#             if disconnected_ips:
#                 st.subheader("🔌 Devices Disconnected")
#                 for ip in disconnected_ips:
#                     enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#                     st.warning(f"{enriched} last seen at `{disconnection_times[ip]}`")

#     session_ips.update(latest_ips)
#     time.sleep(refresh_interval)







# import streamlit as st
# import pandas as pd
# import os
# import re
# import subprocess
# from datetime import datetime, timedelta

# from monitor.scan_local import run_windows_defender_scan
# from monitor.shutdown_network import disable_wifi
# from monitor.alert_admin import send_email_alert
# # from monitor.quarantine import block_ip
# from monitor.file_transfer_watch import pending_transfers

# from manuf import manuf
# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# RESET_INTERVAL_MINUTES = 10
# if "last_reset_time" not in st.session_state:
#     st.session_state.last_reset_time = datetime.now()
# if "session_ips" not in st.session_state:
#     st.session_state.session_ips = set()

# # --- Helpers ---
# def extract_raw_ip(enriched_ip):
#     match = re.match(r"(\d+\.\d+\.\d+\.\d+)", enriched_ip)
#     return match.group(1) if match else enriched_ip

# @st.cache_data(ttl=10)
# def load_data():
#     try:
#         df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

# @st.cache_data(ttl=10)
# def load_alert_log():
#     if not os.path.exists(ALERT_LOG):
#         return pd.DataFrame(columns=["timestamp", "ip", "type", "message"])
#     df = pd.read_csv(ALERT_LOG)
#     df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#     return df.dropna(subset=["timestamp"])

# def log_alert(ip, alert_type, message):
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(ALERT_LOG, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},{ip},{alert_type},"{message}"\n')

# def identify_device(ip):
#     try:
#         output = subprocess.check_output(["arp", "-a"], text=True)
#         for line in output.splitlines():
#             if ip in line:
#                 match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#                 if match:
#                     mac = match.group(0).replace("-", ":").lower()
#                     vendor = mac_parser.get_manuf(mac)
#                     return f"🖥️ {vendor or 'Unknown Vendor'}"
#     except Exception:
#         pass
#     return "❓ Unknown Device"

# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips

# def get_blocked_ips():
#     output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#     blocked = []
#     for line in output.splitlines():
#         if "Rule Name:" in line and "Block_" in line:
#             rule_name = line.split(":")[1].strip()
#             ip = rule_name.split("_")[-1]
#             blocked.append(ip)
#     return list(set(blocked))

# def test_block(ip):
#     result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
# show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
# test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

# if st.sidebar.button("Run Antivirus Scan"):
#     run_windows_defender_scan()
#     st.sidebar.success("Scan triggered.")

# if st.sidebar.button("Disable Wi-Fi"):
#     disable_wifi()
#     st.sidebar.warning("Wi-Fi disabled.")

# if st.sidebar.button("Send Manual Alert"):
#     send_email_alert("192.168.1.5", 99.0)
#     log_alert("192.168.1.5", "manual", "Manual alert triggered")
#     st.sidebar.info("Manual alert sent.")

# # --- File Transfer Approval Panel ---
# st.sidebar.subheader("📥 Pending File Transfers")
# for ip, info in pending_transfers.copy().items():
#     st.sidebar.write(f"{ip} → {info['uri']}")
#     if st.sidebar.button(f"Allow {ip}"):
#         st.sidebar.success(f"✅ Download approved for {ip}")
#         log_alert(ip, "file_transfer", f"Download approved: {info['uri']}")
#         pending_transfers.pop(ip)
#     if st.sidebar.button(f"Block {ip}"):
#         # block_ip(ip)
#         st.sidebar.error(f"⛔ Download blocked for {ip}")
#         log_alert(ip, "file_transfer", f"Download blocked: {info['uri']}")
#         pending_transfers.pop(ip)

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
# if df.empty:
#     st.info("No data yet. Waiting for next scan...")
#     st.stop()

# df["device_type"] = df["ip"].map(identify_device)
# connection_times, disconnection_times, active_ips = track_connections(df)
# latest_ips = set(df["ip"].unique())
# new_ips = latest_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - latest_ips

# # --- Key Metrics Cards ---
# st.subheader("📈 Key Metrics")
# total_devices = len(df["ip"].unique())
# avg_confidence = round(df["confidence"].mean(), 2) if not df.empty else 0
# active_devices = len(active_ips)

# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Detected", total_devices)
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Active Devices", active_devices)

# st.markdown("---")

# # --- Device Logs & Confidence Chart ---
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
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data, width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.success(f"{enriched} connected at `{connection_times[ip]}`")

#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.warning(f"{enriched} last seen at `{disconnection_times[ip]}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         if blocked_ips:
#             for ip in blocked_ips:
#                 status = "✅ Blocked" if test_block(ip) else "❌ Reachable"
#                 st.error(f"{ip} → {status}")
#         else:
#             st.info("No devices currently blocked.")

# st.session_state.session_ips.update(latest_ips)
# st.rerun()



# =========================================================================================================== #


# import streamlit as st
# import pandas as pd
# import os
# import re
# import subprocess
# from datetime import datetime, timedelta
# from streamlit_autorefresh import st_autorefresh

# from monitor.scan_local import run_windows_defender_scan
# from monitor.shutdown_network import disable_wifi
# from monitor.alert_admin import send_email_alert
# # from monitor.quarantine import block_ip
# from monitor.file_transfer_watch import start_file_monitor

# from manuf import manuf
# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# RESET_INTERVAL_MINUTES = 10
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
#     try:
#         df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

# @st.cache_data(ttl=10)
# def get_arp_lines():
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# arp_lines = get_arp_lines()

# def identify_device(ip):
#     for line in arp_lines:
#         if ip in line:
#             match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#             if match:
#                 mac = match.group(0).replace("-", ":").lower()
#                 vendor = mac_parser.get_manuf(mac)
#                 return f"🖥️ {vendor or 'Unknown Vendor'}"
#     return "❓ Unknown Device"

# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips

# def get_blocked_ips():
#     output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#     blocked = []
#     for line in output.splitlines():
#         if "Rule Name:" in line and "Block_" in line:
#             rule_name = line.split(":")[1].strip()
#             ip = rule_name.split("_")[-1]
#             blocked.append(ip)
#     return list(set(blocked))

# def test_block(ip):
#     result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# def log_alert(ip, alert_type, message):
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(ALERT_LOG, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},{ip},{alert_type},"{message}"\n')

# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
# show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
# test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

# if st.sidebar.button("Run Antivirus Scan"):
#     run_windows_defender_scan()
#     st.sidebar.success("Scan triggered.")

# if st.sidebar.button("Disable Wi-Fi"):
#     disable_wifi()
#     st.sidebar.warning("Wi-Fi disabled.")

# if st.sidebar.button("Send Manual Alert"):
#     send_email_alert("192.168.1.5", 99.0)
#     log_alert("192.168.1.5", "manual", "Manual alert triggered")
#     st.sidebar.info("Manual alert sent.")

# # --- File Transfer Approval Panel ---
# st.sidebar.subheader("📥 Pending File Transfers")
# for ip, info in start_file_monitor.copy().items():
#     with st.sidebar.expander(f"{ip} → {info['uri']}"):
#         if st.button(f"✅ Allow {ip}"):
#             st.sidebar.success(f"Download approved for {ip}")
#             log_alert(ip, "file_transfer", f"Download approved: {info['uri']}")
#             start_file_monitor.pop(ip)
#         if st.button(f"⛔ Block {ip}"):
#             # block_ip(ip)
#             st.sidebar.error(f"Download blocked for {ip}")
#             log_alert(ip, "file_transfer", f"Download blocked: {info['uri']}")
#             start_file_monitor.pop(ip)

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
# if df.empty:
#     st.info("No data yet. Waiting for next scan...")
#     st.stop()

# df["device_type"] = df["ip"].map(identify_device)
# connection_times, disconnection_times, active_ips = track_connections(df)
# latest_ips = set(df["ip"].unique())
# new_ips = latest_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - latest_ips

# # --- Key Metrics Cards ---
# st.subheader("📈 Key Metrics")
# total_devices = len(df["ip"].unique())
# avg_confidence = round(df["confidence"].mean(), 2) if not df.empty else 0
# active_devices = len(active_ips)

# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Detected", total_devices)
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Active Devices", active_devices)

# st.markdown("---")

# # --- Device Logs & Confidence Chart ---
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
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data, width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.success(f"{enriched} connected at `{connection_times[ip]}`")

#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.warning(f"{enriched} last seen at `{disconnection_times[ip]}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         for ip in blocked_ips:
#             status = "✅ Blocked" if test_block(ip) else "❌ Reachable"
#             st.error(f"{ip} → {status}")
#     else:
#         st.info("No devices currently blocked.")

# st.session_state.session_ips.update(latest_ips)



# ====================================================================================================== #
# ====================================================================================================== #
# ====================================================================================================== #
# ====================================================================================================== #
# ====================================================================================================== #
# ====================================================================================================== #


# import streamlit as st
# import pandas as pd
# import os
# import re
# import subprocess
# from datetime import datetime, timedelta
# from streamlit_autorefresh import st_autorefresh

# from monitor.scan_local import run_windows_defender_scan
# from monitor.shutdown_network import disable_wifi
# from monitor.alert_admin import send_email_alert
# from monitor.file_transfer_watch import start_file_monitor
# from monitor.domain_watch import start_domain_monitor
# from manuf import manuf

# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# RESET_INTERVAL_MINUTES = 10

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
#     try:
#         df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

# @st.cache_data(ttl=10)
# def load_alerts():
#     try:
#         df = pd.read_csv(ALERT_LOG, names=["timestamp", "ip", "type", "message"], encoding="utf-8")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         return df.dropna(subset=["timestamp"])
#     except Exception:
#         return pd.DataFrame(columns=["timestamp", "ip", "type", "message"])

# @st.cache_data(ttl=10)
# def get_arp_lines():
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# arp_lines = get_arp_lines()

# def identify_device(ip):
#     for line in arp_lines:
#         if ip in line:
#             match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#             if match:
#                 mac = match.group(0).replace("-", ":").lower()
#                 vendor = mac_parser.get_manuf(mac)
#                 return f"🖥️ {vendor or 'Unknown Vendor'}"
#     return "❓ Unknown Device"
# @st.cache_data(ttl=10)
# def load_domain_alerts():
#     try:
#         df = pd.read_csv("data/domain_alerts.csv", names=["timestamp", "domain", "ip", "verdict"])
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         return df.dropna(subset=["timestamp"])
#     except Exception:
#         return pd.DataFrame(columns=["timestamp", "domain", "ip", "verdict"])

# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips

# def get_blocked_ips():
#     output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#     blocked = []
#     for line in output.splitlines():
#         if "Rule Name:" in line and "Block_" in line:
#             rule_name = line.split(":")[1].strip()
#             ip = rule_name.split("_")[-1]
#             blocked.append(ip)
#     return list(set(blocked))

# def test_block(ip):
#     result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
# show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
# test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

# if st.sidebar.button("Run Antivirus Scan"):
#     run_windows_defender_scan()
#     st.sidebar.success("Scan triggered.")

# if st.sidebar.button("Disable Wi-Fi"):
#     disable_wifi()
#     st.sidebar.warning("Wi-Fi disabled.")

# if st.sidebar.button("Send Manual Alert"):
#     send_email_alert("192.168.1.5", 99.0)
#     st.sidebar.info("Manual alert sent.")

# # --- Recent Broadcast Alerts ---
# alert_df = load_alerts()
# st.sidebar.subheader("📢 Recent Alerts")
# for _, row in alert_df.sort_values("timestamp", ascending=False).head(5).iterrows():
#     st.sidebar.warning(f"{row['timestamp']} → {row['message']}")

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
# if df.empty:
#     st.info("No data yet. Waiting for next scan...")
#     st.stop()

# df["device_type"] = df["ip"].map(identify_device)
# connection_times, disconnection_times, active_ips = track_connections(df)
# latest_ips = set(df["ip"].unique())
# new_ips = latest_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - latest_ips

# # --- Key Metrics Cards ---
# st.subheader("📈 Key Metrics")
# total_devices = len(df["ip"].unique())
# avg_confidence = round(df["confidence"].mean(), 2) if not df.empty else 0
# active_devices = len(active_ips)

# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Detected", total_devices)
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Active Devices", active_devices)

# st.markdown("---")

# # --- Device Logs & Confidence Chart ---
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
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data, width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.success(f"{enriched} connected at `{connection_times[ip]}`")

#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.warning(f"{enriched} last seen at `{disconnection_times[ip]}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         for ip in blocked_ips:
#             status = "✅ Blocked" if test_block(ip) else "❌ Reachable"
#             st.error(f"{ip} → {status}")
#     else:
#         st.info("No devices currently blocked.")

# st.session_state.session_ips.update(latest_ips)


# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================


# import streamlit as st
# import pandas as pd
# import os
# import re
# import subprocess
# from datetime import datetime, timedelta
# from streamlit_autorefresh import st_autorefresh
# from manuf import manuf

# from monitor.scan_local import run_windows_defender_scan
# from monitor.shutdown_network import disable_wifi
# from monitor.alert_admin import send_email_alert
# from monitor.domain_watch import start_domain_monitor
# from monitor.file_transfer_watch import start_file_monitor

# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# DOMAIN_LOG = "data/domain_alerts.csv"
# RESET_INTERVAL_MINUTES = 10

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
#     try:
#         df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

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

# @st.cache_data(ttl=10)
# def get_arp_lines():
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# arp_lines = get_arp_lines()

# def identify_device(ip):
#     for line in arp_lines:
#         if ip in line:
#             match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#             if match:
#                 mac = match.group(0).replace("-", ":").lower()
#                 vendor = mac_parser.get_manuf(mac)
#                 return f"🖥️ {vendor or 'Unknown Vendor'}"
#     return "❓ Unknown Device"

# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips

# def get_blocked_ips():
#     output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#     blocked = []
#     for line in output.splitlines():
#         if "Rule Name:" in line and "Block_" in line:
#             rule_name = line.split(":")[1].strip()
#             ip = rule_name.split("_")[-1]
#             blocked.append(ip)
#     return list(set(blocked))

# def test_block(ip):
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

# if st.sidebar.button("Run Antivirus Scan"):
#     run_windows_defender_scan()
#     st.sidebar.success("Scan triggered.")

# if st.sidebar.button("Disable Wi-Fi"):
#     disable_wifi()
#     st.sidebar.warning("Wi-Fi disabled.")

# if st.sidebar.button("Send Manual Alert"):
#     send_email_alert("192.168.1.5", 99.0)
#     st.sidebar.info("Manual alert sent.")

# # --- Recent Broadcast Alerts ---
# alert_df = load_alerts()
# st.sidebar.subheader("📢 Recent Alerts")
# for _, row in alert_df.sort_values("timestamp", ascending=False).head(5).iterrows():
#     st.sidebar.warning(f"{row['timestamp']} → {row['message']}")

# # --- Domain Reputation Alerts ---
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
# if df.empty:
#     st.info("No data yet. Waiting for next scan...")
#     st.stop()

# df["device_type"] = df["ip"].map(identify_device)
# connection_times, disconnection_times, active_ips = track_connections(df)
# latest_ips = set(df["ip"].unique())
# new_ips = latest_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - latest_ips

# # --- Key Metrics Cards ---
# st.subheader("📈 Key Metrics")
# total_devices = len(df["ip"].unique())
# avg_confidence = round(df["confidence"].mean(), 2) if not df.empty else 0
# active_devices = len(active_ips)

# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Detected", total_devices)
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Active Devices", active_devices)

# st.markdown("---")

# # --- Device Logs & Confidence Chart ---
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
#         chart_data = df.pivot(index="timestamp", columns="ip", values="confidence")
#         st.line_chart(chart_data,width='stretch')

#     if show_domain_alerts and not domain_df.empty:
#         with st.expander("🌐 View Full Domain Alert Log"):
#             st.dataframe(domain_df.sort_values("timestamp", ascending=False),width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data,width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.success(f"{enriched} connected at `{connection_times[ip]}`")

#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             enriched = df[df["ip"] == ip]["enriched_ip"].iloc[0]
#             st.warning(f"{enriched} last seen at `{disconnection_times[ip]}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         if blocked_ips:
#             for ip in blocked_ips:
#                 status = "✅ Blocked" if test_blocking and test_block(ip) else "⚠️ Rule exists"
#                 st.error(f"{ip} → {status}")
#         else:
#             st.info("No devices currently blocked.")



# def load_recent_file_transfers(limit=10):
#     path = "data/file_transfer_log.csv"
#     if not os.path.exists(path):
#         return []

#     with open(path, "r", encoding="utf-8") as f:
#         lines = f.readlines()[-limit:]
#         return [line.strip().split(",") for line in lines]

# def render_file_transfer_panel():
#     entries = load_recent_file_transfers()
#     st.subheader("📁 Recent File Transfers")
#     if not entries:
#         st.info("No file transfers detected yet.")
#         return

#     for timestamp, ip, summary in entries:
#         st.warning(f"[{timestamp}] {ip} → {summary}")



# ================================================================================================================
# ================================================================================================================
# ================================================================================================================
# ================================================================================================================
# ================================================================================================================




# import streamlit as st
# import pandas as pd
# import os
# import re
# import subprocess
# from datetime import datetime, timedelta
# from streamlit_autorefresh import st_autorefresh
# from manuf import manuf

# from monitor.scan_local import run_windows_defender_scan
# from monitor.shutdown_network import disable_wifi
# from monitor.alert_admin import send_email_alert
# from monitor.domain_watch import start_domain_monitor

# mac_parser = manuf.MacParser()

# # --- Page config ---
# st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# # --- Constants ---
# LOG_FILE = "data/prediction_log.csv"
# ALERT_LOG = "data/alert_log.csv"
# DOMAIN_LOG = "data/domain_alerts.csv"
# FILE_LOG = "data/file_transfer_log.csv"
# RESET_INTERVAL_MINUTES = 10

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
#     try:
#         df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
#         df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
#         df["ip"] = df["enriched_ip"].map(extract_raw_ip)
#         df.dropna(subset=["timestamp"], inplace=True)
#         return df
#     except Exception as e:
#         st.error(f"Failed to load log file: {e}")
#         return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

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

# @st.cache_data(ttl=10)
# def load_recent_file_transfers(limit=10):
#     path = "data/file_transfer_log.csv"
#     if not os.path.exists(path):
#         return []

#     with open(path, "r", encoding="utf-8") as f:
#         lines = f.readlines()[-limit:]
#         entries = []
#         for line in lines:
#             parts = line.strip().split(",")
#             if len(parts) >= 3:
#                 entries.append([parts[0], parts[1], ",".join(parts[2:])])
#         return entries


# @st.cache_data(ttl=10)
# def get_arp_lines():
#     try:
#         return subprocess.check_output(["arp", "-a"], text=True).splitlines()
#     except Exception:
#         return []

# arp_lines = get_arp_lines()

# def identify_device(ip):
#     for line in arp_lines:
#         if ip in line:
#             match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
#             if match:
#                 mac = match.group(0).replace("-", ":").lower()
#                 vendor = mac_parser.get_manuf(mac)
#                 return f"🖥️ {vendor or 'Unknown Vendor'}"
#     return "❓ Unknown Device"
# def get_connected_ips_from_arp():
#     ips = set()
#     for line in arp_lines:
#         match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
#         if match:
#             ips.add(match.group(0))
#     return ips

# def track_connections(df):
#     connection_times, disconnection_times, active_ips = {}, {}, set()
#     for ip in df["ip"].unique():
#         ip_data = df[df["ip"] == ip].sort_values("timestamp")
#         connection_times[ip] = ip_data["timestamp"].iloc[0]
#         disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
#         active_ips.add(ip)
#     return connection_times, disconnection_times, active_ips

# def get_blocked_ips():
#     output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
#     blocked = []
#     for line in output.splitlines():
#         if "Rule Name:" in line and "Block_" in line:
#             rule_name = line.split(":")[1].strip()
#             ip = rule_name.split("_")[-1]
#             blocked.append(ip)
#     return list(set(blocked))

# def test_block(ip):
#     result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# def render_file_transfer_panel():
#     entries = load_recent_file_transfers()
#     st.subheader("📁 Recent File Transfers")
#     if not entries:
#         st.info("No file transfers detected yet.")
#         return

#     df_ft = pd.DataFrame(entries, columns=["timestamp", "ip", "summary"])
#     df_ft["timestamp"] = pd.to_datetime(df_ft["timestamp"], errors="coerce")
#     df_ft = df_ft.dropna(subset=["timestamp"])

#     st.dataframe(df_ft.sort_values("timestamp", ascending=False), width='stretch')

#     with st.expander("📁 View Full File Transfer Log"):
#         st.dataframe(df_ft, width='stretch')


# # --- Sidebar ---
# st.sidebar.title("📊 Dashboard Controls")
# refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
# show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
# show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
# show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
# show_domain_alerts = st.sidebar.checkbox("Show Domain Alerts", value=True)
# show_file_transfers = st.sidebar.checkbox("Show File Transfers", value=True)
# test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

# if st.sidebar.button("Run Antivirus Scan"):
#     run_windows_defender_scan()
#     st.sidebar.success("Scan triggered.")

# if st.sidebar.button("Disable Wi-Fi"):
#     disable_wifi()
#     st.sidebar.warning("Wi-Fi disabled.")

# if st.sidebar.button("Send Manual Alert"):
#     send_email_alert("192.168.1.5", 99.0)
#     st.sidebar.info("Manual alert sent.")

# # --- Recent Broadcast Alerts ---
# alert_df = load_alerts()
# st.sidebar.subheader("📢 Recent Alerts")
# for _, row in alert_df.sort_values("timestamp", ascending=False).head(5).iterrows():
#     st.sidebar.warning(f"{row['timestamp']} → {row['message']}")

# # --- Domain Reputation Alerts ---
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
# if df.empty:
#     st.info("No data yet. Waiting for next scan...")
#     st.stop()

# df["device_type"] = df["ip"].map(identify_device)
# connection_times, disconnection_times, active_ips = track_connections(df)
# latest_ips = set(df["ip"].unique())
# new_ips = latest_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - latest_ips

# # --- Key Metrics + Device Tracking ---
# st.subheader("📈 Key Metrics")

# # Define active window (in minutes)
# ACTIVE_WINDOW_MINUTES = 5
# cutoff_time = datetime.now() - timedelta(minutes=ACTIVE_WINDOW_MINUTES)

# # Filter active entries
# active_df = df[df["timestamp"] >= cutoff_time]
# active_ips = set(active_df["ip"].unique())

# # Track all seen IPs this session
# latest_ips = set(df["ip"].unique())
# new_ips = active_ips - st.session_state.session_ips
# disconnected_ips = st.session_state.session_ips - active_ips

# # Classify devices
# suspicious_devices = active_df[active_df["status"] != "benign"]["ip"].nunique()
# benign_devices = len(active_ips) - suspicious_devices
# avg_confidence = round(active_df["confidence"].mean(), 2) if not active_df.empty else 0

# # Metrics
# col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Connected", len(active_ips))
# col2.metric("📊 Average Confidence", avg_confidence)
# col3.metric("🟢 Benign Devices", benign_devices)

# st.markdown("---")


# # --- File Transfer Panel ---
# if show_file_transfers:
#     render_file_transfer_panel()

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
#         chart_data = df.pivot_table(index="timestamp", columns="ip", values="confidence", aggfunc="mean")
#         st.line_chart(chart_data, width='stretch')

#     if show_domain_alerts and not domain_df.empty:
#         with st.expander("🌐 View Full Domain Alert Log"):
#             st.dataframe(domain_df.sort_values("timestamp", ascending=False), width='stretch')

# with col2:
#     if show_timeline:
#         st.subheader("🕒 Device Presence Timeline")
#         timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
#         timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
#         st.dataframe(timeline_data, width='stretch')

#     if new_ips:
#         st.subheader("🆕 New Devices Connected")
#         for ip in new_ips:
#             match = df[df["ip"] == ip]
#             enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
#             first_seen = match["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
#             st.success(f"{enriched} connected at `{first_seen}`")
#     if disconnected_ips:
#         st.subheader("🔌 Devices Disconnected")
#         for ip in disconnected_ips:
#             match = df[df["ip"] == ip]
#             enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
#             last_seen = match["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
#             st.warning(f"{enriched} last seen at `{last_seen}`")

#     if show_blocked:
#         st.subheader("🚫 Quarantine Status")
#         blocked_ips = get_blocked_ips()
#         if blocked_ips:
#             for ip in blocked_ips:
#                 status = "✅ Blocked" if test_blocking and test_block(ip) else "⚠️ Rule exists"
#                 st.error(f"{ip} → {status}")
#         else:
#             st.info("No devices currently blocked.")

# # Update session state
# st.session_state.session_ips = active_ips



# ============================================================================================================ 
# ============================================================================================================ 
# ============================================================================================================ 
# ============================================================================================================ 
# ============================================================================================================ 



import os
import re
import subprocess
import pandas as pd
import streamlit as st
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh
from manuf import manuf

mac_parser = manuf.MacParser()

# --- Page config ---
st.set_page_config(page_title="Botnet Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- Constants ---
LOG_FILE = "data/prediction_log.csv"
ALERT_LOG = "data/alert_log.csv"
DOMAIN_LOG = "data/domain_alerts.csv"
RESET_INTERVAL_MINUTES = 10
ACTIVE_WINDOW_MINUTES = 5
st_autorefresh(interval=5000, limit=None, key="arp_refresh")

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
    try:
        df = pd.read_csv(LOG_FILE, names=["timestamp", "enriched_ip", "confidence", "status"], encoding="utf-8", quotechar='"', on_bad_lines="skip")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["ip"] = df["enriched_ip"].map(extract_raw_ip)
        df.dropna(subset=["timestamp"], inplace=True)
        return df
    except Exception as e:
        st.error(f"Failed to load log file: {e}")
        return pd.DataFrame(columns=["timestamp", "enriched_ip", "confidence", "status", "ip"])

@st.cache_data(ttl=10)
def load_alerts():
    try:
        df = pd.read_csv(ALERT_LOG, names=["timestamp", "ip", "type", "message"], encoding="utf-8")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.dropna(subset=["timestamp"])
    except Exception:
        return pd.DataFrame(columns=["timestamp", "ip", "type", "message"])

@st.cache_data(ttl=10)
def load_domain_alerts():
    try:
        df = pd.read_csv(DOMAIN_LOG, names=["timestamp", "domain", "ip", "verdict"])
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.dropna(subset=["timestamp"])
    except Exception:
        return pd.DataFrame(columns=["timestamp", "domain", "ip", "verdict"])

@st.cache_data(ttl=10)
def get_arp_lines():
    try:
        return subprocess.check_output(["arp", "-a"], text=True).splitlines()
    except Exception:
        return []

def get_connected_ips_from_arp():
    ips = set()
    for line in get_arp_lines():
        match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if match:
            ip = match.group(0)
            # Exclude multicast, broadcast, and reserved IPs
            if (
                not ip.startswith("224.") and
                not ip.startswith("239.") and
                not ip.endswith(".255") and
                ip != "255.255.255.255"
            ):
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

def track_connections(df):
    connection_times, disconnection_times = {}, {}
    for ip in df["ip"].unique():
        ip_data = df[df["ip"] == ip].sort_values("timestamp")
        connection_times[ip] = ip_data["timestamp"].iloc[0]
        disconnection_times[ip] = ip_data["timestamp"].iloc[-1]
    return connection_times, disconnection_times

def get_blocked_ips():
    output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True)
    blocked = []
    for line in output.splitlines():
        if "Rule Name:" in line and "Block_" in line:
            rule_name = line.split(":")[1].strip()
            ip = rule_name.split("_")[-1]
            blocked.append(ip)
    return list(set(blocked))

def test_block(ip):
    result = subprocess.run(["ping", ip, "-n", "2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return "Destination host unreachable" in result.stdout or "Request timed out" in result.stdout

# --- Sidebar ---
st.sidebar.title("Dashboard Controls →")
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
show_timeline = st.sidebar.checkbox("Show Device Timeline", value=True)
show_chart = st.sidebar.checkbox("Show Confidence Chart", value=True)
show_blocked = st.sidebar.checkbox("Show Blocked Devices", value=True)
show_domain_alerts = st.sidebar.checkbox("Show Domain Alerts", value=True)
test_blocking = st.sidebar.checkbox("Test Device Blocking", value=False)

alert_df = load_alerts()
st.sidebar.subheader("Recent Alerts or Notifications ↓")
for _, row in alert_df.sort_values("timestamp", ascending=False).head(5).iterrows():
    st.sidebar.warning(f"{row['timestamp']} → {row['message']}")

if show_domain_alerts:
    domain_df = load_domain_alerts()
    st.sidebar.subheader("Domain Reputation Alerts ↓")
    for _, row in domain_df.sort_values("timestamp", ascending=False).head(5).iterrows():
        verdict_icon = "🟥" if row["verdict"] == "malicious" else "🟨" if row["verdict"] == "suspicious" else "🟩"
        st.sidebar.warning(f"{verdict_icon} {row['timestamp']} → {row['domain']} ({row['ip']}) → {row['verdict']}")

# --- Main Dashboard ---


# Custom CSS for glowing text
st.markdown("""
    <style>
    .glow-title {
        font-size: 50px;
        font-weight: 900;
        text-align: center;
        color: #00ffff;
        text-shadow: 0 0 10px #00ffff,
                     0 0 20px #00ffff,
                     0 0 30px #00ffff,
                     0 0 40px #00ffff,
                     0 0 70px #00ffff,
                     0 0 80px #00ffff,
                     0 0 100px #00ffff;
        font-family: 'Trebuchet MS', sans-serif;
        margin-bottom: 40px;
        animation: glow 2s ease-in-out infinite alternate;
    }

    @keyframes glow {
        from {
            text-shadow: 0 0 10px #00ffff,
                         0 0 20px #00ffff,
                         0 0 30px #00ffff,
                         0 0 40px #00ffff;
        }
        to {
            text-shadow: 0 0 20px #ff00ff,
                         0 0 30px #ff00ff,
                         0 0 40px #ff00ff,
                         0 0 50px #ff00ff,
                         0 0 80px #ff00ff;
        }
    }
    </style>

    <h1 class="glow-title">→ Bot-Net Detection ←</h1>
""", unsafe_allow_html=True)


# Refresh every 5 seconds
st_autorefresh(interval=5000, limit=None, key="device_count_refresh")


# Show live connected device count first
arp_ips = get_connected_ips_from_arp()
connected_count = len(arp_ips)

# st.subheader("💻 Connected Devices Now (Live ARP Scan)")
# st.metric(label="Devices Connected", value=connected_count)

# Optional: wait briefly before loading rest of dashboard
st.markdown("---")

# Auto-clear log
if datetime.now() - st.session_state.last_reset_time > timedelta(minutes=RESET_INTERVAL_MINUTES):
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, "w", encoding="utf-8").close()
        st.toast(f"🧹 Cleared {LOG_FILE} at {datetime.now().strftime('%H:%M:%S')}")
    st.session_state.last_reset_time = datetime.now()
    st.session_state.session_ips.clear()

if not os.path.exists(LOG_FILE):
    st.warning("Waiting for log file...")
    st.stop()

df = load_data()
df["device_type"] = df["ip"].map(identify_device)

# Merge ARP IPs with prediction log
arp_ips = get_connected_ips_from_arp()

# Track changes
previous_ips = st.session_state.get("session_ips", set())
new_ips = arp_ips - previous_ips
disconnected_ips = previous_ips - arp_ips
st.session_state.session_ips = arp_ips

# Display
st.subheader("💻 Connected Devices Realtime (Live ARP Scan)")
st.metric("Devices Connected", len(arp_ips))

if new_ips:
    st.success(f"🆕 New Devices: {', '.join(sorted(new_ips))}")
if disconnected_ips:
    st.warning(f"🔌 Disconnected Devices: {', '.join(sorted(disconnected_ips))}")


# Filter active entries
cutoff_time = datetime.now() - timedelta(minutes=ACTIVE_WINDOW_MINUTES)
active_df = df[df["timestamp"] >= cutoff_time]
active_ips = arp_ips.union(set(active_df["ip"].unique()))

# Track new/disconnected devices
new_ips = active_ips - st.session_state.session_ips
disconnected_ips = st.session_state.session_ips - active_ips

# --- Key Metrics ---
st.subheader("📈 Key Metrics")
suspicious_devices = active_df[active_df["status"] != "benign"]["ip"].nunique()
benign_devices = len(active_ips) - suspicious_devices
avg_confidence = round(active_df["confidence"].mean(), 2) if not active_df.empty else 0

col1, col2, col3 = st.columns(3)
# col1.metric("💻 Total Devices Connected", len(active_ips))
col2.metric("📊 Average Confidence", avg_confidence)
col3.metric("🟢 Benign Devices", benign_devices)

st.markdown("---")

# --- Device Confidence Log ---
col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("📋 Device Confidence Log")

    # Extract device name and vendor
    df["device_name"] = df["enriched_ip"].str.extract(r"\((.*?)\)")
    df["mac_vendor"] = df["ip"].map(lambda ip: identify_device(ip).replace("🖥️ ", "").replace("❓ ", ""))
    df["accuracy"] = df["confidence"]

    # Placeholder for file_status (can be linked to file_transfer_log.csv)
    df["file_status"] = df["status"].apply(lambda s: "⚠️ suspicious transfer" if s == "botnet" else "✅ safe")

    # Restore transfer_type column if available
    if "transfer_type" not in df.columns:
        df["transfer_type"] = "unknown"

    display_df = df.sort_values("timestamp", ascending=False)[
        ["timestamp", "ip", "device_name", "mac_vendor", "accuracy", "status", "file_status", "transfer_type"]
    ]

    st.dataframe(display_df, width='stretch', hide_index=True)

    if show_chart:
        st.subheader("📈 Accuracy Over Time")
        chart_data = df.pivot_table(index="timestamp", columns="ip", values="accuracy", aggfunc="mean")
        st.line_chart(chart_data,width='stretch')

    if show_domain_alerts and not domain_df.empty:
        with st.expander("🌐 View Full Domain Alert Log"):
            st.dataframe(domain_df.sort_values("timestamp", ascending=False), width='stretch')

with col2:
    if show_timeline:
        st.subheader("🕒 Device Presence Timeline")
        timeline_data = df.groupby("ip")["timestamp"].agg(["min", "max"])
        timeline_data["duration"] = timeline_data["max"] - timeline_data["min"]
        st.dataframe(timeline_data, width='stretch')

    if new_ips:
        st.subheader("🆕 New Devices Connected")
        for ip in new_ips:
            match = df[df["ip"] == ip]
            enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
            first_seen = match["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
            st.success(f"{enriched} connected at `{first_seen}`")

    if disconnected_ips:
        st.subheader("🔌 Devices Disconnected")
        for ip in disconnected_ips:
            match = df[df["ip"] == ip]
            enriched = match["enriched_ip"].iloc[0] if not match.empty else ip
            last_seen = match["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not match.empty else "Unknown"
            st.warning(f"{enriched} last seen at `{last_seen}`")

    if show_blocked:
        st.subheader("🚫 Quarantine Status")
        blocked_ips = get_blocked_ips()
        if blocked_ips:
            for ip in blocked_ips:
                status = "✅ Blocked" if test_blocking and test_block(ip) else "⚠️ Rule exists"
                st.error(f"{ip} → {status}")
        else:
            st.info("No devices currently blocked.")

# Update session state
st.session_state.session_ips = active_ips

