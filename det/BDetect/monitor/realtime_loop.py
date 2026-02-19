# import time
# import json
# from capture.capture_traffic import scan_connected_devices, get_gateway_ip
# from capture.capture_traffic import capture_device_traffic
# from preprocess.convert_pcap_to_png import convert_pcap_to_png
# from model.inference import predict_image, load_model
# from monitor.alert_admin import send_email_alert
# from monitor.notify_devices import broadcast_alert

# def load_thresholds(path="config/thresholds.json"):
#     try:
#         with open(path, "r") as f:
#             return json.load(f)
#     except Exception as e:
#         print(f"[!] Failed to load thresholds config: {e}")
#         return {"confidence_threshold": 50.0, "scan_interval_seconds": 60}

# def monitor_loop():
#     print("[🔍] Starting real-time botnet detection loop...")
#     model = load_model()
#     seen_devices = set()
#     config = load_thresholds()
#     CONFIDENCE_THRESHOLD = config["confidence_threshold"]
#     SCAN_INTERVAL = config["scan_interval_seconds"]

#     while True:
#         try:
#             gateway_ip = get_gateway_ip()
#             devices = scan_connected_devices(gateway_ip)

#             for device in devices:
#                 ip = device["ip"]
#                 if ip not in seen_devices:
#                     print(f"[+] New device detected: {ip}")
#                     pcap_path = capture_device_traffic(ip)
#                     image_path = convert_pcap_to_png(pcap_path)
#                     confidence = predict_image(model, image_path)

#                     print(f"[📊] Confidence for {ip}: {confidence:.2f}%")
#                     if confidence < CONFIDENCE_THRESHOLD:
#                         print(f"[⚠️] Botnet suspected on {ip}")
#                         send_email_alert(ip, confidence)
#                         broadcast_alert(ip)

#                     seen_devices.add(ip)

#             time.sleep(SCAN_INTERVAL)

#         except Exception as e:
#             print(f"[!] Error in monitoring loop: {e}")
#             time.sleep(10)  # brief pause before retry

# if __name__ == "__main__":
#     monitor_loop()




# monitor/realtime_loop.py

from capture.scan_wifi import scan_connected_devices
from capture.capture_traffic import capture_device_traffic
from preprocess.convert_pcap_to_png import convert_pcap_to_png
from model.inference import load_model, predict_image
from monitor.notify_devices import send_email_alert, broadcast_alert, show_popup_alert

import time
import os

def monitor_loop():
    print("[🔍] Starting real-time botnet detection loop...")
    model = load_model()
    seen_devices = set()

    while True:
        try:
            devices = scan_connected_devices()
            for device in devices:
                ip = device["ip"]
                if ip not in seen_devices:
                    print(f"[🆕] New device detected: {ip}")
                    seen_devices.add(ip)
                    status = "new"
                else:
                    status = None

                pcap_path = capture_device_traffic(ip)
                image_path = convert_pcap_to_png(pcap_path)
                if image_path is None or not os.path.exists(image_path):
                    print(f"[!] No image generated for {ip}, skipping.")
                    continue

                confidence = predict_image(image_path, model)
                print(f"[📊] Confidence for {ip}: {confidence:.2f}%")

                if status != "new":
                    status = "benign" if confidence >= 70 else "suspicious"
                    if confidence < 70:
                        print(f"[⚠️] Botnet suspected on {ip}")
                        send_email_alert(ip, confidence)
                        broadcast_alert(ip)
                        show_popup_alert(ip)

                # Log result
                with open("data/results.csv", "a") as f:
                    f.write(f"{ip},{confidence:.2f},{status}\n")

            time.sleep(60)

        except Exception as e:
            print(f"[!] Error in monitoring loop: {e}")
            time.sleep(10)

if __name__ == "__main__":
    monitor_loop()
