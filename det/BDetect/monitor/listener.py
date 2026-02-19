import socket
import threading
import time
from plyer import notification

PORT = 9999
BUFFER_SIZE = 1024

def show_popup(title, message):
    try:
        notification.notify(title=title, message=message, timeout=10)
        print(f"[🔔] Notification triggered: {title} → {message}")
    except Exception as e:
        print(f"[❌] Popup failed: {e}")

def listen_for_alerts():
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

if __name__ == "__main__":
    threading.Thread(target=listen_for_alerts, daemon=True).start()
    print("[🚀] Alert listener running...")
    while True:
        time.sleep(1)
