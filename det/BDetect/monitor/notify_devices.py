# import socket

# def broadcast_alert(ip):
#     message = f"⚠️ Botnet detected on {ip}. Please disconnect from WiFi immediately."
#     broadcast_ip = "255.255.255.255"
#     port = 5005

#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(message.encode(), (broadcast_ip, port))
#         print(f"[📢] Broadcast alert sent to all devices.")
#     except Exception as e:
#         print(f"[!] Failed to broadcast alert: {e}")
#     finally:
#         sock.close()

# # if __name__ == "__main__":
# #     test_ip = input("Enter IP to broadcast alert for: ")
# #     broadcast_alert(test_ip)



# monitor/notify_devices/broadcast_alert.py

# import socket
# import json
# import os
# import yagmail,time
# import logging
# from plyer import notification

# # 🔧 Broadcast alert to all devices
# # def broadcast_alert(message, port=9999):
# #     broadcast_ip = "192.168.1.255"  # Force correct broadcast IP
# #     try:
# #         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
# #             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# #             sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
# #             print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
# #             logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
# #     except Exception as e:
# #         print(f"[❌] Broadcast failed: {e}")
# #         logging.error(f"Failed to send broadcast alert: {e}")


# # 💬 Show popup alert on local machine
# # def show_popup_alert(ip):
# #     notification.notify(
# #         title="⚠️ Botnet Detected",
# #         message=f"Suspicious device on {ip}. Disconnect immediately.",
# #         timeout=10
# #     )
# #     print(f"[💬] Popup alert shown for {ip}")

# def show_popup_alert(title, message):
#     try:
#         from plyer import notification
#         notification.notify(
#             title=title,
#             message=message,
#             timeout=10  # You can increase this if needed
#         )
#         print(f"[🔔] Notification triggered: {title} → {message}")
#         time.sleep(2)  # Give OS time to render
#     except Exception as e:
#         print(f"[❌] Plyer failed: {e}. Using fallback popup.")
#         try:
#             import ctypes
#             ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # Warning icon, stays until dismissed
#         except Exception as fallback_error:
#             print(f"[❌] Fallback popup failed: {fallback_error}")


# # 📧 Send email alert to admin
# def load_email_config(config_path="config/email_config.json"):
#     if not os.path.exists(config_path):
#         raise FileNotFoundError("Email config file not found.")
#     with open(config_path, "r") as f:
#         return json.load(f)

# def send_email_alert(ip, confidence):
#     config = load_email_config()
#     yag = yagmail.SMTP(config["sender_email"], config["sender_password"])
#     subject = "⚠️ Botnet Alert: Suspicious Device Detected"
#     body = f"""
#     A new device connected to the WiFi with suspicious behavior.

#     IP Address: {ip}
#     Confidence Score: {confidence:.2f}%

#     Recommended Action: Investigate and disconnect the device immediately.
#     """
#     yag.send(to=config["admin_email"], subject=subject, contents=body)
#     print(f"[📨] Alert email sent to admin: {config['admin_email']}")



# ==========================08-10=25============================


import socket
import json
import os
import yagmail
import time
import logging
from plyer import notification

PORT = 9999
BUFFER_SIZE = 1024

# 💬 Show popup alert on local machine
def show_popup_alert(title, message):
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=10
        )
        print(f"[🔔] Notification triggered: {title} → {message}")
        time.sleep(2)
    except Exception as e:
        print(f"[❌] Plyer failed: {e}. Using fallback popup.")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)
        except Exception as fallback_error:
            print(f"[❌] Fallback popup failed: {fallback_error}")

# 📧 Send email alert to admin
def load_email_config(config_path="config/email_config.json"):
    if not os.path.exists(config_path):
        raise FileNotFoundError("Email config file not found.")
    with open(config_path, "r") as f:
        return json.load(f)

def send_email_alert(ip, confidence):
    config = load_email_config()
    yag = yagmail.SMTP(config["sender_email"], config["sender_password"])
    subject = "⚠️ Botnet Alert: Suspicious Device Detected"
    body = f"""
    A new device connected to the WiFi with suspicious behavior.

    IP Address: {ip}
    Confidence Score: {confidence:.2f}%

    Recommended Action: Investigate and disconnect the device immediately.
    """
    yag.send(to=config["admin_email"], subject=subject, contents=body)
    print(f"[📨] Alert email sent to admin: {config['admin_email']}")

# 📡 Send UDP alert (broadcast or targeted)
def send_udp_alert(message, broadcast=False, target_ip=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(message.encode("utf-8"), ("<broadcast>", PORT))
            print(f"[📢] Broadcast alert sent → {message}")
        elif target_ip:
            sock.sendto(message.encode("utf-8"), (target_ip, PORT))
            print(f"[📬] Targeted alert sent to {target_ip} → {message}")
        sock.close()
    except Exception as e:
        print(f"[❌] UDP alert failed: {e}")
        logging.error(f"UDP alert failed: {e}")
