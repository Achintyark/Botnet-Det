# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import os
# import time
# from datetime import datetime

# # Define model class to match training architecture
# seen_devices = set()

# import torch.nn as nn
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     with open(log_file, "a") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f"{timestamp},{ip},{confidence:.2f},{status}\n")

# if __name__ == "__main__":
#     model = load_model()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")
#     while True:
#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {ip}, skipping.")
#                     continue
#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {ip} → Confidence benign: {confidence:.2f}%")
#                 status = "benign" if confidence >= 70 else "suspicious"
#                 if confidence < 70:
#                     print(f"[⚠️] ALERT: {ip} may be suspicious!")
#                 log_result(ip, confidence, status)
#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")
#         print("[⏳] Waiting 60 seconds before next scan...\n")
#         time.sleep(60)




# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import os
# import time
# from datetime import datetime

# # Define model class to match training architecture
# import torch.nn as nn
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     with open(log_file, "a") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f"{timestamp},{ip},{confidence:.2f},{status}\n")

# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")
#     while True:
#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {ip}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None  # will be set after prediction

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {ip}, skipping.")
#                     continue
#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {ip} → Confidence benign: {confidence:.2f}%")

#                 if status != "new":
#                     status = "benign" if confidence >= 70 else "suspicious"
#                     if confidence < 70:
#                         print(f"[⚠️] ALERT: {ip} may be suspicious!")

#                 log_result(ip, confidence, status)
#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")
#         print("[⏳] Waiting 60 seconds before next scan...\n")
#         time.sleep(60)


# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import os
# import time
# import json
# from datetime import datetime
# import torch.nn as nn

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]

# # Telegram config (replace with your actual values)
# BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
# CHAT_ID = "YOUR_CHAT_ID"

# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     with open(log_file, "a") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f"{timestamp},{ip},{confidence:.2f},{status}\n")

# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")
#     while True:
#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {ip}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {ip}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {ip} → Confidence benign: {confidence:.2f}%")

#                 show_prediction_image(image_path)

#                 if status != "new":
#                     status = "benign" if confidence >= CONFIDENCE_THRESHOLD else "suspicious"
#                     if confidence < CONFIDENCE_THRESHOLD:
#                         print(f"[⚠️] ALERT: {ip} may be suspicious!")
#                         send_email_alert(ip, confidence)
#                         broadcast_alert(ip)
#                         show_popup_alert(ip)
#                         send_telegram_alert(ip, confidence, BOT_TOKEN, CHAT_ID)

#                 log_result(ip, confidence, status)

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)




# import threading
# import subprocess
# import os
# import time
# import json
# from datetime import datetime

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# from monitor.quarantine import block_ip
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]

# # Telegram config
# BOT_TOKEN = "8324783319:AAHl78HCC5ZDrJcteSxSGLHKm37GgF9ZOvo"
# CHAT_ID = "1609312246"

# # Model definition
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     with open(log_file, "a") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f"{timestamp},{ip},{confidence:.2f},{status}\n")

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     # Start dashboard in a separate thread
#     threading.Thread(target=launch_dashboard, daemon=True).start()

#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")
#     while True:
#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {ip}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {ip}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {ip} → Confidence benign: {confidence:.2f}%")

#                 # show_prediction_image(image_path)
                

#                 if status != "new":
#                     status = "benign" if confidence >= CONFIDENCE_THRESHOLD else "suspicious"
#                     if confidence < CONFIDENCE_THRESHOLD:
#                         print(f"[⚠️] ALERT: {ip} may be suspicious!")
#                         send_email_alert(ip, confidence)
#                         broadcast_alert(ip)
#                         show_popup_alert(ip)
#                         send_telegram_alert(ip, confidence)
#                         block_ip(ip)

#                 log_result(ip, confidence, status)

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)





# =========================================================================================================================== 


# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import re
# import socket
# import ipaddress
# from datetime import datetime

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# from monitor.quarantine import block_ip
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]

# # Telegram config
# BOT_TOKEN = "8324783319:AAHl78HCC5ZDrJcteSxSGLHKm37GgF9ZOvo"
# CHAT_ID = "1609312246"

# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     plat = platform.system().lower()
#     try:
#         if "windows" in plat:
#             out = subprocess.check_output(["arp", "-a"], text=True)
#         else:
#             out = subprocess.check_output(["arp", "-n"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         m = re.search(r"(\d+\.\d+\.\d+\.\d+).+?([0-9a-fA-F]{2}[:-](?:[0-9a-fA-F]{2}[:-]){4}[0-9a-fA-F]{2})", line)
#         if m:
#             ip = m.group(1)
#             mac = m.group(2).replace("-", ":").lower()
#             entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')  # remove stray quotes
#     with open(log_file, "a", encoding="utf-8") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")

#     while True:
#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {enriched}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 # show_prediction_image(image_path)

#                 status = "benign" if confidence >= CONFIDENCE_THRESHOLD else "suspicious"

#                 if confidence < CONFIDENCE_THRESHOLD:
#                     print(f"[⚠️] ALERT: {enriched} may be suspicious!")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(ip)
#                     show_popup_alert(ip)
#                     send_telegram_alert(ip, confidence)
#                     block_ip(ip)

#                 log_result(ip, confidence, status)

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)




# =======================



# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import re
# import socket
# import ipaddress
# from datetime import datetime

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# from monitor.quarantine import block_ip
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]

# # Telegram config
# BOT_TOKEN = "8324783319:AAHl78HCC5ZDrJcteSxSGLHKm37GgF9ZOvo"
# CHAT_ID = "1609312246"

# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     plat = platform.system().lower()
#     try:
#         if "windows" in plat:
#             out = subprocess.check_output(["arp", "-a"], text=True)
#         else:
#             out = subprocess.check_output(["arp", "-n"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         m = re.search(r"(\d+\.\d+\.\d+\.\d+).+?([0-9a-fA-F]{2}[:-](?:[0-9a-fA-F]{2}[:-]){4}[0-9a-fA-F]{2})", line)
#         if m:
#             ip = m.group(1)
#             mac = m.group(2).replace("-", ":").lower()
#             entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- ARP Refresh -----------------
# def refresh_arp_cache(subnet="192.168.0.0/24"):
#     print(f"[↻] Refreshing ARP cache with ping sweep on {subnet}...")
#     for i in range(1, 255):
#         ip = f"192.168.0.{i}"
#         subprocess.Popen(["ping", ip, "-n", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         confidence = torch.softmax(output, dim=1)[0][0].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')  # remove stray quotes
#     with open(log_file, "a", encoding="utf-8") as f:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")

#     while True:
#         refresh_arp_cache("192.168.0.0/24")  # Actively populate ARP cache
#         time.sleep(5)  # Give time for responses

#         devices = scan_connected_devices()
#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {enriched}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 # show_prediction_image(image_path)

#                 status = "benign" if confidence >= CONFIDENCE_THRESHOLD else "suspicious"

#                 if confidence < CONFIDENCE_THRESHOLD:
#                     print(f"[⚠️] ALERT: {enriched} may be suspicious!")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(ip)
#                     show_popup_alert(ip)
#                     send_telegram_alert(ip, confidence)
#                     block_ip(ip)

#                 log_result(ip, confidence, status)

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)



# ================================================================================================================= #



# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import re
# import socket
# import ipaddress
# from datetime import datetime

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# from monitor.quarantine import block_ip
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]

# # Telegram config
# BOT_TOKEN = "8324783319:AAHl78HCC5ZDrJcteSxSGLHKm37GgF9ZOvo"
# CHAT_ID = "1609312246"

# # ----------------- Dynamic Subnet Detection -----------------
# def get_local_subnet():
#     try:
#         hostname = socket.gethostname()
#         local_ip = socket.gethostbyname(hostname)
#         subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
#         return subnet
#     except Exception:
#         return "192.168.0.0/24"  # fallback

# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     plat = platform.system().lower()
#     try:
#         if "windows" in plat:
#             out = subprocess.check_output(["arp", "-a"], text=True)
#         else:
#             out = subprocess.check_output(["arp", "-n"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         m = re.search(r"(\d+\.\d+\.\d+\.\d+).+?([0-9a-fA-F]{2}[:-](?:[0-9a-fA-F]{2}[:-]){4}[0-9a-fA-F]{2})", line)
#         if m:
#             ip = m.group(1)
#             mac = m.group(2).replace("-", ":").lower()
#             entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- ARP Refresh -----------------
# def refresh_arp_cache(subnet):
#     print(f"[↻] Refreshing ARP cache with ping sweep on {subnet}...")
#     base = subnet.split("/")[0].rsplit(".", 1)[0]
#     for i in range(1, 255):
#         ip = f"{base}.{i}"
#         subprocess.Popen(["ping", ip, "-n", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         probs = torch.softmax(output, dim=1)[0]
#         predicted_class = torch.argmax(probs).item()
#         confidence = probs[predicted_class].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(log_file, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")

#     while True:
#         subnet = get_local_subnet()
#         refresh_arp_cache(subnet)
#         time.sleep(5)

#         devices = scan_connected_devices()
#         print(f"[📡] Discovered devices: {[d['ip'] for d in devices]}")

#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {enriched}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 status = "benign" if confidence >= CONFIDENCE_THRESHOLD else "suspicious"

#                 if confidence < CONFIDENCE_THRESHOLD:
#                     print(f"[⚠️] ALERT: {enriched} may be suspicious!")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(ip)
#                     show_popup_alert(ip)
#                     send_telegram_alert(ip, confidence)
#                     block_ip(ip)

#                 log_result(ip, confidence, status)

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)



# ========================================================================================================== #



# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import socket
# import ipaddress
# from datetime import datetime

# import scapy.all as scapy

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert
# from monitor.push_alerts import send_telegram_alert
# # from monitor.quarantine import block_ip
# from monitor.domain_watch import start_domain_monitor
# from monitor.file_transfer_watch import start_file_monitor
# from monitor.scan_malwarebytes import run_malwarebytes_scan
# from model.explain_prediction import show_prediction_image

# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]
# BOT_TOKEN = config.get("telegram_bot_token", "")
# CHAT_ID = config.get("telegram_chat_id", "")

# # ----------------- Dynamic IP + Subnet -----------------
# def get_active_interface_ip():
#     for iface in scapy.get_if_list():
#         try:
#             ip = scapy.get_if_addr(iface)
#             if ipaddress.ip_address(ip).is_private and not ip.startswith("169.254.") and ip != "0.0.0.0":
#                 return ip
#         except Exception:
#             continue
#     return None


# def get_subnet_from_ip(ip):
#     try:
#         iface = scapy.conf.iface
#         netmask = scapy.get_if_netmask(iface)
#         network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
#         return str(network)
#     except Exception:
#         return ".".join(ip.split(".")[:3]) + ".0/24"


# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     try:
#         out = subprocess.check_output(["arp", "-a"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         if "dynamic" in line or "static" in line:
#             parts = line.split()
#             if len(parts) >= 2:
#                 ip = parts[0]
#                 mac = parts[1].replace("-", ":").lower()
#                 entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- ARP Refresh -----------------
# def refresh_arp_cache(subnet):
#     print(f"[↻] Refreshing ARP cache with ping sweep on {subnet}...")
#     base = subnet.split("/")[0].rsplit(".", 1)[0]
#     for i in range(1, 255):
#         ip = f"{base}.{i}"
#         subprocess.call(["ping", ip, "-n", "1", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(b"M-SEARCH * HTTP/1.1\r\n", ("239.255.255.250", 1900))
#         sock.close()
#         print("[📡] Broadcast UDP sent to wake devices.")
#     except Exception as e:
#         print(f"[!] Broadcast failed: {e}")
#     time.sleep(3)

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         probs = torch.softmax(output, dim=1)[0]
#         predicted_class = torch.argmax(probs).item()
#         confidence = probs[predicted_class].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(log_file, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     threading.Thread(target=start_domain_monitor, daemon=True).start()
#     threading.Thread(target=start_file_monitor, daemon=True).start()

#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")

#     while True:
#         local_ip = get_active_interface_ip()
#         if not local_ip:
#             print("[❌] No valid local IP found. Skipping scan.")
#             time.sleep(SCAN_INTERVAL)
#             continue

#         subnet = get_subnet_from_ip(local_ip)
#         print(f"[🌐] Detected local IP: {local_ip}")
#         print(f"[🌐] Scanning subnet: {subnet}")
#         refresh_arp_cache(subnet)

#         devices = scan_connected_devices()
#         print(f"[📡] Discovered devices: {[d['ip'] for d in devices]}]")

#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {enriched}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 if confidence >= CONFIDENCE_THRESHOLD:
#                     status = "benign"
#                     print(f"[✅] {enriched} classified as benign.")

#                 else:
#                     status = "suspicious"
#                     print(f"[⚠️] ALERT: {enriched} may be suspicious!")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(ip)
#                     send_telegram_alert(ip, confidence)
#                     show_popup_alert(ip)


#                     # block_ip(ip)
#                 log_result(ip, confidence, status)    

#                 try:
#                     run_malwarebytes_scan()
#                 except Exception as e:
#                     print(f"[!] Malwarebytes scan failed for {ip}: {e}")
                

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)



# ======================================================
# ======================================================
# ======================================================
# ======================================================
# ======================================================

# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import socket
# import ipaddress
# from datetime import datetime

# import scapy.all as scapy

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, show_popup_alert
# from monitor.broadcast_alert import broadcast_alert
# from monitor.push_alerts import send_telegram_alert
# # from monitor.quarantine import block_ip
# from monitor.domain_watch import start_domain_monitor
# from monitor.scan_malwarebytes import run_malwarebytes_scan
# from model.explain_prediction import show_prediction_image
# from monitor.file_transfer_watch import start_file_transfer_monitor
# from dashboard import render_file_transfer_panel
# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]
# BOT_TOKEN = config.get("telegram_bot_token", "")
# CHAT_ID = config.get("telegram_chat_id", "")



# # ----------------- Dynamic IP + Subnet -----------------
# def get_active_interface_ip():
#     for iface in scapy.get_if_list():
#         try:
#             ip = scapy.get_if_addr(iface)
#             if ipaddress.ip_address(ip).is_private and not ip.startswith("169.254.") and ip != "0.0.0.0":
#                 return ip
#         except Exception:
#             continue
#     return None

# def get_subnet_from_ip(ip):
#     try:
#         iface = scapy.conf.iface
#         netmask = scapy.get_if_netmask(iface)
#         network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
#         return str(network)
#     except Exception:
#         return ".".join(ip.split(".")[:3]) + ".0/24"

# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     try:
#         out = subprocess.check_output(["arp", "-a"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         if "dynamic" in line or "static" in line:
#             parts = line.split()
#             if len(parts) >= 2:
#                 ip = parts[0]
#                 mac = parts[1].replace("-", ":").lower()
#                 entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- ARP Refresh -----------------
# def refresh_arp_cache(subnet):
#     print(f"[↻] Refreshing ARP cache with ping sweep on {subnet}...")
#     base = subnet.split("/")[0].rsplit(".", 1)[0]
#     for i in range(1, 255):
#         ip = f"{base}.{i}"
#         subprocess.call(["ping", ip, "-n", "1", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(b"M-SEARCH * HTTP/1.1\r\n", ("239.255.255.250", 1900))
#         sock.close()
#         print("[📡] Broadcast UDP sent to wake devices.")
#     except Exception as e:
#         print(f"[!] Broadcast failed: {e}")
#     time.sleep(3)

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         probs = torch.softmax(output, dim=1)[0]
#         predicted_class = torch.argmax(probs).item()
#         confidence = probs[predicted_class].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(log_file, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')

# def launch_dashboard():
#     print("[📊] Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     threading.Thread(target=start_domain_monitor, daemon=True).start()
#     threading.Thread(target=start_file_transfer_monitor, daemon=True).start()

#     print("[🚀] Real-time botnet detection started. Press Ctrl+C to stop.")

#     while True:
#         local_ip = get_active_interface_ip()
#         if not local_ip:
#             print("[❌] No valid local IP found. Skipping scan.")
#             time.sleep(SCAN_INTERVAL)
#             continue

#         subnet = get_subnet_from_ip(local_ip)
#         print(f"[🌐] Detected local IP: {local_ip}")
#         print(f"[🌐] Scanning subnet: {subnet}")
#         refresh_arp_cache(subnet)

#         devices = scan_connected_devices()
#         print(f"[📡] Discovered devices: {[d['ip'] for d in devices]}")

#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"[🆕] New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"[!] No image generated for {enriched}, skipping.")
#                     continue

#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 if confidence >= CONFIDENCE_THRESHOLD:
#                     status = "benign"
#                     print(f"[✅] {enriched} classified as benign.")
#                 else:
#                     status = "suspicious"
#                     print(f"[⚠️] ALERT: {enriched} may be suspicious!")

#                     alert_message = f"Botnet detected on {ip}"
#                     print(f"[📢] Sending broadcast alert: {alert_message}")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(alert_message)
#                     send_telegram_alert(ip, confidence)
#                     show_popup_alert("⚠️ Botnet Detected", f"Suspicious device on {ip}. Disconnect immediately.")


#                     # block_ip(ip)

#                 log_result(ip, confidence, status)

#                 try:
#                     run_malwarebytes_scan()
#                 except Exception as e:
#                     print(f"[!] Malwarebytes scan failed for {ip}: {e}")

#             except Exception as e:
#                 print(f"[!] Skipping {ip}: {e}")

#         print(f"[⏳] Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)

# # ======================================================




# import threading
# import subprocess
# import os
# import time
# import json
# import platform
# import socket
# import ipaddress
# from datetime import datetime

# import scapy.all as scapy

# from capture.scan_wifi import scan_connected_devices
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from monitor.notify_devices import send_email_alert, show_popup_alert
# from monitor.broadcast_alert import broadcast_alert
# from monitor.push_alerts import send_telegram_alert
# from monitor.domain_watch import start_domain_monitor
# from monitor.scan_malwarebytes import run_malwarebytes_scan
# from monitor.file_transfer_watch import start_file_transfer_monitor
# # from dashboard import render_file_transfer_panel
# import torch
# import torchvision.transforms as transforms
# from PIL import Image
# import torch.nn as nn

# # Optional: manuf for MAC vendor lookup
# try:
#     from manuf import manuf
#     mac_parser = manuf.MacParser()
# except Exception:
#     mac_parser = None

# # Load thresholds
# with open("config/thresholds.json", "r") as f:
#     config = json.load(f)
# CONFIDENCE_THRESHOLD = config["confidence_threshold"]
# SCAN_INTERVAL = config["scan_interval_seconds"]
# BOT_TOKEN = config.get("telegram_bot_token", "")
# CHAT_ID = config.get("telegram_chat_id", "")

# # ----------------- Dynamic IP + Subnet -----------------
# def get_active_interface_ip():
#     for iface in scapy.get_if_list():
#         try:
#             ip = scapy.get_if_addr(iface)
#             if ipaddress.ip_address(ip).is_private and not ip.startswith("169.254.") and ip != "0.0.0.0":
#                 return ip
#         except Exception:
#             continue
#     return None

# def get_subnet_from_ip(ip):
#     try:
#         iface = scapy.conf.iface
#         netmask = scapy.get_if_netmask(iface)
#         network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
#         return str(network)
#     except Exception:
#         return ".".join(ip.split(".")[:3]) + ".0/24"

# # ----------------- IP Enrichment -----------------
# def read_arp_table():
#     try:
#         out = subprocess.check_output(["arp", "-a"], text=True)
#     except Exception:
#         return {}
#     entries = {}
#     for line in out.splitlines():
#         if "dynamic" in line or "static" in line:
#             parts = line.split()
#             if len(parts) >= 2:
#                 ip = parts[0]
#                 mac = parts[1].replace("-", ":").lower()
#                 entries[ip] = mac
#     return entries

# def reverse_dns(ip):
#     try:
#         return socket.gethostbyaddr(ip)[0]
#     except Exception:
#         return ""

# def mac_vendor(mac):
#     if not mac_parser:
#         return ""
#     try:
#         return mac_parser.get_manuf(mac) or ""
#     except Exception:
#         return ""

# def enrich_ip(ip):
#     if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
#         return ip
#     arp = read_arp_table()
#     mac = arp.get(ip, "unknown")
#     hostname = reverse_dns(ip)
#     vendor = mac_vendor(mac)
#     return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

# # ----------------- ARP Refresh -----------------
# def refresh_arp_cache(subnet):
#     print(f"^^^    Refreshing ARP cache with ping sweep on {subnet}...")
#     base = subnet.split("/")[0].rsplit(".", 1)[0]
#     for i in range(1, 255):
#         ip = f"{base}.{i}"
#         subprocess.call(["ping", ip, "-n", "1", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(b"M-SEARCH * HTTP/1.1\r\n", ("239.255.255.250", 1900))
#         sock.close()
#         print("###---   Broadcast UDP sent to wake devices.")
#     except Exception as e:
#         print(f"!!!    Broadcast failed: {e}")
#     time.sleep(3)

# # ----------------- Model -----------------
# class Net(nn.Module):
#     def __init__(self):
#         super(Net, self).__init__()
#         self.net = nn.Sequential(
#             nn.Conv2d(1, 16, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Conv2d(16, 32, 3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool2d(2),
#             nn.Flatten(),
#             nn.Linear(32 * 8 * 8, 64),
#             nn.ReLU(),
#             nn.Linear(64, 2)
#         )

#     def forward(self, x):
#         return self.net(x)

# def load_model(model_path="model/model.pth"):
#     print("@@@   Loading classification model...")
#     model = Net()
#     state_dict = torch.load(model_path)
#     model.load_state_dict(state_dict)
#     model.eval()
#     print("@@@@@   Model loaded successfully.   @@@@")
#     return model

# def predict_image(image_path, model):
#     transform = transforms.Compose([
#         transforms.Grayscale(),
#         transforms.Resize((32, 32)),
#         transforms.ToTensor()
#     ])
#     image = Image.open(image_path)
#     input_tensor = transform(image).unsqueeze(0)
#     with torch.no_grad():
#         output = model(input_tensor)
#         probs = torch.softmax(output, dim=1)[0]
#         predicted_class = torch.argmax(probs).item()
#         confidence = probs[predicted_class].item() * 100
#         return confidence

# def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
#     os.makedirs(os.path.dirname(log_file), exist_ok=True)
#     enriched = enrich_ip(ip).replace('"', '')
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     with open(log_file, "a", encoding="utf-8") as f:
#         f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')
#     print(f"&&&   Logged result for {ip} → {status} ({confidence:.2f}%)")

# def launch_dashboard():
#     print("------>>>>>>>   Launching Streamlit dashboard...")
#     subprocess.Popen(["streamlit", "run", "dashboard.py"])

# def launch_monitors():
#     print("------->>>>>>>   Launching domain monitor thread...")
#     threading.Thread(target=start_domain_monitor, daemon=True).start()
#     print("------->>>>>>>   Domain monitor thread started.")

#     print("------->>>>>>>   Launching file transfer monitor thread...")
#     threading.Thread(target=start_file_transfer_monitor, daemon=True).start()
#     print("------->>>>>>>  File transfer monitor thread started.")

# # ----------------- Main Loop -----------------
# if __name__ == "__main__":
#     model = load_model()
#     seen_devices = set()

#     threading.Thread(target=launch_dashboard, daemon=True).start()
#     launch_monitors()

#     print("************---  Real-time botnet detection started. Press Ctrl+C to stop. ")

#     while True:
#         local_ip = get_active_interface_ip()
#         if not local_ip:
#             print("!!!!!! ---  No valid local IP found. Skipping scan.   !!!!!!")
#             time.sleep(SCAN_INTERVAL)
#             continue

#         subnet = get_subnet_from_ip(local_ip)
#         print(f"------------>>>>>   Detected local IP: {local_ip}   <<<<<<<<<<------")
#         print(f"------------>>>>>   Scanning subnet: {subnet}   <<<<<<<------")
#         refresh_arp_cache(subnet)

#         devices = scan_connected_devices()
#         print(f"^^^^^^^^^^^--- Discovered devices: {[d['ip'] for d in devices]}  --- ^^^^^^^^^^^")

#         for device in devices:
#             ip = device["ip"]
#             try:
#                 enriched = enrich_ip(ip)
#                 if ip not in seen_devices:
#                     print(f"#####--- New device connected: {enriched}")
#                     status = "new"
#                     seen_devices.add(ip)
#                 else:
#                     status = None

#                 print(f"&&&&&Capturing traffic for {ip} on {scapy.conf.iface} for 30 seconds...")
#                 pcap_path = capture_device_traffic(ip, duration=30)
#                 print(f"@@@@--- Saved to {pcap_path}")

#                 image_path = convert_pcap_to_png(pcap_path)
#                 if image_path is None or not os.path.exists(image_path):
#                     print(f"!!!!!!--- No image generated for {enriched}, skipping.")
#                     continue

#                 print(f"@@@@@@--- Saved image: {image_path}")
#                 confidence = predict_image(image_path, model)
#                 print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

#                 if confidence >= CONFIDENCE_THRESHOLD:
#                     status = "benign"
#                     print(f"$$$--->    {enriched} classified as benign.")
#                 else:
#                     status = "suspicious"
#                     print(f"###--->     ALERT: {enriched} may be suspicious!")

#                     alert_message = f"Botnet detected on {ip}"
#                     print(f"&&&--->     Sending broadcast alert: {alert_message}")
#                     send_email_alert(ip, confidence)
#                     broadcast_alert(alert_message)
#                     send_telegram_alert(ip, confidence)
#                     show_popup_alert("!!!------>>>   Botnet Detected", f"Suspicious device on {ip}. Disconnect immediately.")

#                 log_result(ip, confidence, status)

#                 try:
#                     run_malwarebytes_scan()
#                 except Exception as e:
#                     print(f"!!!--->    Malwarebytes scan failed for {ip}: {e}")

#             except Exception as e:
#                 print(f"!!!--->    Skipping {ip} due to error: {e}")

#         print(f"@@@--->     Waiting {SCAN_INTERVAL} seconds before next scan...\n")
#         time.sleep(SCAN_INTERVAL)



# ===============================================08-10-25========================================

# main.py

import threading
import subprocess
import os
import time
import json
import platform
import socket
import ipaddress
from datetime import datetime

import scapy.all as scapy

from capture.scan_wifi import scan_connected_devices
from capture.capture_traffic import capture_device_traffic
from preprocess.convert_pcap_to_png import convert_pcap_to_png
from monitor.notify_devices import send_email_alert, show_popup_alert
from monitor.broadcast_alert import broadcast_alert
from monitor.push_alerts import send_telegram_alert
from monitor.domain_watch import start_domain_monitor
from monitor.scan_malwarebytes import run_malwarebytes_scan
# from monitor.file_transfer_watch import start_file_transfer_monitor
import torch
import torchvision.transforms as transforms
from PIL import Image
import torch.nn as nn

try:
    from manuf import manuf
    mac_parser = manuf.MacParser()
except Exception:
    mac_parser = None


import socket
from plyer import notification

PORT = 9999
BUFFER_SIZE = 1024

def show_popup(title, message):
    try:
        notification.notify(title=title, message=message, timeout=10)
        print(f"[🔔] Notification triggered: {title} → {message}")
    except Exception as e:
        print(f"[❌] Popup failed: {e}")
def log_received_alert(message, sender_ip, log_file="data/received_alerts.csv"):
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{timestamp},{sender_ip},{message}\n")
        print(f"[📝] Logged alert from {sender_ip}")
    except Exception as e:
        print(f"[❌] CSV log error: {e}")

def listen_for_alerts():
    message = data.decode("utf-8", errors="replace")
    sender_ip = addr[0]
    print(f"[📥] Alert received from {sender_ip}: {message}")
    show_popup("📢 Network Alert", message)
    log_received_alert(message, sender_ip)

    print(f"[🟢] Listening for alerts on port {PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", PORT))
        print(f"[✅] Bound to port {PORT}. Waiting for alerts...")
    except Exception as e:
        print(f"[❌] Bind error: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = data.decode("utf-8", errors="replace")
            print(f"[📥] Alert received from {addr[0]}: {message}")
            show_popup("📢 Network Alert", message)
        except Exception as e:
            print(f"[❌] Receive error: {e}")

with open("config/thresholds.json", "r") as f:
    config = json.load(f)
CONFIDENCE_THRESHOLD = config["confidence_threshold"]
SCAN_INTERVAL = config["scan_interval_seconds"]
BOT_TOKEN = config.get("telegram_bot_token", "")
CHAT_ID = config.get("telegram_chat_id", "")

def get_active_interface_ip():
    for iface in scapy.get_if_list():
        try:
            ip = scapy.get_if_addr(iface)
            if ipaddress.ip_address(ip).is_private and not ip.startswith("169.254.") and ip != "0.0.0.0":
                return ip
        except Exception:
            continue
    return None

def get_subnet_from_ip(ip):
    try:
        iface = scapy.conf.iface
        netmask = scapy.get_if_netmask(iface)
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return ".".join(ip.split(".")[:3]) + ".0/24"

def read_arp_table():
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
    except Exception:
        return {}
    entries = {}
    for line in out.splitlines():
        if "dynamic" in line or "static" in line:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1].replace("-", ":").lower()
                entries[ip] = mac
    return entries

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def mac_vendor(mac):
    if not mac_parser:
        return ""
    try:
        return mac_parser.get_manuf(mac) or ""
    except Exception:
        return ""

def enrich_ip(ip):
    if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
        return ip
    arp = read_arp_table()
    mac = arp.get(ip, "unknown")
    hostname = reverse_dns(ip)
    vendor = mac_vendor(mac)
    return f"{ip} → {hostname or 'Unknown'} (MAC: {mac}, Vendor: {vendor or 'Unknown'})"

def refresh_arp_cache(subnet):
    print(f"^^^    Refreshing ARP cache with ping sweep on {subnet}...")
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    for i in range(1, 255):
        ip = f"{base}.{i}"
        subprocess.call(["ping", ip, "-n", "1", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(b"M-SEARCH * HTTP/1.1\r\n", ("239.255.255.250", 1900))
        sock.close()
        print("###---   Broadcast UDP sent to wake devices.")
    except Exception as e:
        print(f"!!!    Broadcast failed: {e}")
    time.sleep(3)

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.net = nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Conv2d(16, 32, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Flatten(),
            nn.Linear(32 * 8 * 8, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        return self.net(x)

def load_model(model_path="model/model.pth"):
    print("@@@   Loading classification model...")
    model = Net()
    state_dict = torch.load(model_path)
    model.load_state_dict(state_dict)
    model.eval()
    print("@@@@@   Model loaded successfully.   @@@@")
    return model

def predict_image(image_path, model):
    transform = transforms.Compose([
        transforms.Grayscale(),
        transforms.Resize((32, 32)),
        transforms.ToTensor()
    ])
    image = Image.open(image_path)
    input_tensor = transform(image).unsqueeze(0)
    with torch.no_grad():
        output = model(input_tensor)
        probs = torch.softmax(output, dim=1)[0]
        predicted_class = torch.argmax(probs).item()
        confidence = probs[predicted_class].item() * 100
        return confidence

def log_result(ip, confidence, status, log_file="data/prediction_log.csv"):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    enriched = enrich_ip(ip).replace('"', '')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f'{timestamp},"{enriched}",{confidence:.2f},{status}\n')
    print(f"&&&   Logged result for {ip} → {status} ({confidence:.2f}%)")

def launch_dashboard():
    print("------>>>>>>>   Launching Streamlit dashboard...")
    subprocess.Popen(["streamlit", "run", "dashboard.py"])

def launch_monitors():
    print("------->>>>>>>   Launching domain monitor thread...")
    threading.Thread(target=start_domain_monitor, daemon=True).start()
    print("------->>>>>>>   Domain monitor thread started.")

    print("------->>>>>>>   Launching file transfer monitor thread...")
    # threading.Thread(target=start_file_transfer_monitor, daemon=True).start()
    # print("------->>>>>>>  File transfer monitor thread started.")

if __name__ == "__main__":
    model = load_model()
    seen_devices = set()

    threading.Thread(target=launch_dashboard, daemon=True).start()
    launch_monitors()

    print("************---  Real-time botnet detection started. Press Ctrl+C to stop. ")

    while True:
        local_ip = get_active_interface_ip()
        if not local_ip:
            print("!!!!!! ---  No valid local IP found. Skipping scan.   !!!!!!")
            time.sleep(SCAN_INTERVAL)
            continue

        subnet = get_subnet_from_ip(local_ip)
        print(f"------------>>>>>   Detected local IP: {local_ip}   <<<<<<<<<<------")
        print(f"------------>>>>>   Scanning subnet: {subnet}   <<<<<<<------")
        refresh_arp_cache(subnet)

        devices = scan_connected_devices()
        print(f"^^^^^^^^^^^--- Discovered devices: {[d['ip'] for d in devices]}  --- ^^^^^^^^^^^")

        for device in devices:
            ip = device["ip"]
            try:
                enriched = enrich_ip(ip)
                if ip not in seen_devices:
                    print(f"#####--- New device connected: {enriched}")
                    status = "new"
                    seen_devices.add(ip)
                else:
                    status = None

                print(f"&&&&&Capturing traffic for {ip} on {scapy.conf.iface} for 30 seconds...")
                pcap_path = capture_device_traffic(ip, duration=30)
                print(f"@@@@--- Saved to {pcap_path}")

                image_path = convert_pcap_to_png(pcap_path)
                if image_path is None or not os.path.exists(image_path):
                    print(f"!!!!!!--- No image generated for {enriched}, skipping.")
                    continue

                print(f"@@@@@@--- Saved image: {image_path}")
                confidence = predict_image(image_path, model)
                print(f"[🔍] {enriched} → Confidence benign: {confidence:.2f}%")

                if confidence >= CONFIDENCE_THRESHOLD:
                    status = "benign"
                    print(f"$$$--->    {enriched} classified as benign.")
                else:
                    status = "suspicious"
                    print(f"###--->     ALERT: {enriched} may be suspicious!")

                    alert_message = (
                        f"🚨 Botnet detected on {ip}\n"
                        f"🔍 Confidence: {confidence:.2f}%\n"
                        f"⚠️ Action: Investigate and disconnect immediately."
                    )

                    print(f"&&&--->     Sending alerts for {ip}")
                    send_email_alert(ip, confidence)
                    broadcast_alert(alert_message, target_ip=ip)  # ✅ Only to main system + this device
                    send_telegram_alert(ip, confidence)
                    show_popup_alert("🚨 Botnet Detected", f"Suspicious device on {ip}. Disconnect immediately.")

                log_result(ip, confidence, status)

                try:
                    run_malwarebytes_scan()
                except Exception as e:
                    print(f"!!!--->    Malwarebytes scan failed for {ip}: {e}")

            except Exception as e:
                print(f"!!!--->    Skipping {ip} due to error: {e}")

        print(f"@@@--->     Waiting {SCAN_INTERVAL} seconds before next scan...\n")
        time.sleep(SCAN_INTERVAL)

import subprocess
import threading
import time

arp_cache = {}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.0.1"

def refresh_arp_passive():
    try:
        subnet = ".".join(get_local_ip().split(".")[:3])
        for i in range(1, 50):
            ip = f"{subnet}.{i}"
            subprocess.Popen(["ping", ip, "-n", "1", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[⚠️] Passive ARP refresh failed: {e}")

def background_arp_refresh():
    print("[🌀] ARP thread started in main.py")
    while True:
        try:
            refresh_arp_passive()
            time.sleep(1)
            lines = subprocess.check_output(["arp", "-a"], text=True).splitlines()
            new_cache = {}
            for line in lines:
                if "dynamic" in line or "static" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").lower()
                        if not ip.startswith(("224.", "239.")) and not ip.endswith(".255") and ip != "255.255.255.255":
                            new_cache[ip] = mac
            global arp_cache
            arp_cache = new_cache
            print(f"[📊] ARP cache: {list(arp_cache.keys())}")
        except Exception as e:
            print(f"[❌] ARP refresh failed: {e}")
        time.sleep(5)

def launch_dashboard():
    print("------>>>>>>>   Launching Streamlit dashboard...")
    subprocess.Popen(["streamlit", "run", "dashboard.py"])

def start_arp_thread():
    threading.Thread(target=background_arp_refresh, daemon=True).start()

if __name__ == "__main__":
    threading.Thread(target=background_arp_refresh, daemon=True).start()
    threading.Thread(target=listen_for_alerts, daemon=True).start()
    print("[🚀] Main system running with alert listener...")
    subprocess.Popen(["streamlit", "run", "dashboard.py"])
    while True:
        time.sleep(1)


