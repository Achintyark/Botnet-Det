# import yagmail
# import json
# import os
# from plyer import notification

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


# def show_popup_alert(ip):
#     notification.notify(
#         title="⚠️ Botnet Detected",
#         message=f"Suspicious device on {ip}. Disconnect immediately.",
#         timeout=10  # seconds
#     )
#     print(f"[💬] Popup alert shown for {ip}")


# if __name__ == "__main__":
#     send_email_alert("192.168.0.101", 42.7)




import yagmail
import json
import os
from plyer import notification

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

# def show_popup_alert(ip):
#     notification.notify(
#         title="⚠️ Botnet Detected",
#         message=f"Suspicious device on {ip}. Disconnect immediately.",
#         timeout=10
#     )
#     print(f"[💬] Popup alert shown for {ip}")



# import time
# from plyer import notification
# import ctypes

# def show_popup_alert(title, message):
#     try:
#         notification.notify(
#             title=title,
#             message=message,
#             timeout=10
#         )
#         print(f"[🔔] Notification triggered: {title} → {message}")
#         time.sleep(2)  # Give OS time to render
#     except Exception as e:
#         print(f"[❌] Plyer failed: {e}. Using fallback popup.")
#         try:
#             ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # Warning icon
#         except Exception as fallback_error:
#             print(f"[❌] Fallback popup failed: {fallback_error}")



# ========================================= 08 - 10 -25 =======================================

import time
from plyer import notification
import ctypes

def show_popup_alert(title, message):
    """
    Display a system notification. If plyer fails, fallback to Windows MessageBox.
    """
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=10  # seconds
        )
        print(f"[🔔] Notification triggered: {title} → {message}")
        time.sleep(2)  # Allow time for OS to render
    except Exception as e:
        print(f"[❌] Plyer failed: {e}. Using fallback popup.")
        try:
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # Warning icon
            print(f"[⚠️] Fallback MessageBox shown: {title} → {message}")
        except Exception as fallback_error:
            print(f"[❌] Fallback popup failed: {fallback_error}")
