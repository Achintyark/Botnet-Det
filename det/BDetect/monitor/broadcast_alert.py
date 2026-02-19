
# import socket
# import logging

# def broadcast_alert(message, port=9999):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#         sock.sendto(message.encode(), ('<broadcast>', port))
#         print(f"[📢] Broadcast alert sent: {message}")
#         logging.info(f"Broadcast alert sent: {message}")
#     except Exception as e:
#         logging.error(f"[❌] Failed to send broadcast alert: {e}")




# import socket
# import logging

# # Optional: configure logging to file
# logging.basicConfig(filename="broadcast_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# def broadcast_alert(message, port=9999):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             sock.sendto(message.encode("utf-8"), ('<broadcast>', port))
#             print(f"[📢] Broadcast alert sent: {message}")
#             logging.info(f"Broadcast alert sent: {message}")
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")





# import socket
# import logging
# import ipaddress

# logging.basicConfig(filename="broadcast_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# def get_broadcast_ip():
#     try:
#         hostname = socket.gethostname()
#         local_ip = socket.gethostbyname(hostname)
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         return str(network.broadcast_address)
#     except Exception as e:
#         logging.error(f"Failed to determine broadcast IP: {e}")
#         return "255.255.255.255"

# def broadcast_alert(message, port=9999):
#     try:
#         broadcast_ip = get_broadcast_ip()
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#             print(f"[📢] Broadcast alert sent to {broadcast_ip}: {message}")
#             logging.info(f"Broadcast alert sent to {broadcast_ip}: {message}")
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")



# ==================

# import socket
# import logging
# import ipaddress

# # Setup logging
# logging.basicConfig(
#     filename="broadcast_log.txt",
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# def get_local_ip():
#     try:
#         hostname = socket.gethostname()
#         local_ip = socket.gethostbyname(hostname)
#         print(f"[🌐] Local IP detected: {local_ip}")
#         return local_ip
#     except Exception as e:
#         print(f"[❌] Failed to get local IP: {e}")
#         logging.error(f"Failed to get local IP: {e}")
#         return None

# def get_broadcast_ip(local_ip):
#     try:
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         broadcast_ip = str(network.broadcast_address)
#         print(f"[📡] Calculated broadcast IP: {broadcast_ip}")
#         return broadcast_ip
#     except Exception as e:
#         print(f"[❌] Failed to calculate broadcast IP: {e}")
#         logging.error(f"Failed to calculate broadcast IP: {e}")
#         return "255.255.255.255"

# def broadcast_alert(message, port=9999):
#     local_ip = get_local_ip()
#     broadcast_ip = get_broadcast_ip(local_ip)
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#             print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#             logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")


# # Optional: test broadcast directly
# if __name__ == "__main__":
#     test_message = "Botnet detected on 192.168.0.103"
#     print(f"[🧪] Sending test broadcast: {test_message}")
#     broadcast_alert(test_message)


# ===================================



# import socket
# import logging
# import ipaddress
# import time

# # Setup logging
# log_path = "logs/broadcast_log.txt"
# logging.basicConfig(
#     filename=log_path,
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# def get_local_ip():
#     """Detect the active local IP address."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))  # External target to force routing
#             local_ip = s.getsockname()[0]
#         print(f"[🌐] Local IP detected: {local_ip}")
#         return local_ip
#     except Exception as e:
#         print(f"[❌] Failed to get local IP: {e}")
#         logging.error(f"Failed to get local IP: {e}")
#         return None

# def get_broadcast_ip(local_ip):
#     """Calculate broadcast IP based on local IP and assumed /24 subnet."""
#     try:
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         broadcast_ip = str(network.broadcast_address)
#         print(f"[📡] Calculated broadcast IP: {broadcast_ip}")
#         return broadcast_ip
#     except Exception as e:
#         print(f"[❌] Failed to calculate broadcast IP: {e}")
#         logging.error(f"Failed to calculate broadcast IP: {e}")
#         return "255.255.255.255"

# def broadcast_alert(message, port=9999, retries=1, delay=0.5):
#     """Send a UDP broadcast alert to the local subnet."""
#     local_ip = get_local_ip()
#     if not local_ip:
#         print("[⚠️] Cannot send broadcast: local IP unavailable.")
#         return

#     broadcast_ip = get_broadcast_ip(local_ip)
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             for attempt in range(retries):
#                 sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#                 print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 time.sleep(delay)
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")

# # Optional: test broadcast directly
# if __name__ == "__main__":
#     local_ip = get_local_ip()
#     if local_ip:
#         timestamp = time.strftime("%H:%M:%S")
#         test_message = f"[{timestamp}] Botnet detected on {local_ip}"
#         print(f"[🧪] Sending test broadcast: {test_message}")
#         broadcast_alert(test_message)
#     else:
#         print("[❌] Skipping broadcast test: no local IP.")



# import socket
# import logging
# import ipaddress
# import time

# # Setup logging
# log_path = "logs/broadcast_log.txt"
# logging.basicConfig(
#     filename=log_path,
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# MAIN_SYSTEM_IP = "192.168.1.1"  # 🔧 Replace with your actual main system IP

# def get_local_ip():
#     """Detect the active local IP address."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))
#             local_ip = s.getsockname()[0]
#         print(f"[🌐] Local IP detected: {local_ip}")
#         return local_ip
#     except Exception as e:
#         print(f"[❌] Failed to get local IP: {e}")
#         logging.error(f"Failed to get local IP: {e}")
#         return None

# def get_broadcast_ip(local_ip):
#     """Calculate broadcast IP based on local IP and assumed /24 subnet."""
#     try:
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         broadcast_ip = str(network.broadcast_address)
#         print(f"[📡] Calculated broadcast IP: {broadcast_ip}")
#         return broadcast_ip
#     except Exception as e:
#         print(f"[❌] Failed to calculate broadcast IP: {e}")
#         logging.error(f"Failed to calculate broadcast IP: {e}")
#         return "255.255.255.255"

# def send_udp(message, target_ip, port=9999):
#     """Send a UDP message to a specific IP."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.sendto(message.encode("utf-8"), (target_ip, port))
#             print(f"[📨] Alert sent to {target_ip}:{port} → {message}")
#             logging.info(f"Alert sent to {target_ip}:{port} → {message}")
#     except Exception as e:
#         print(f"[❌] Failed to send alert to {target_ip}: {e}")
#         logging.error(f"Failed to send alert to {target_ip}: {e}")

# def broadcast_alert(message, target_ip=None, port=9999, retries=1, delay=0.5):
#     """
#     Send alert to:
#     - Main system (always)
#     - Specific listener (if target_ip is provided)
#     - Broadcast subnet (if target_ip is None)
#     """
#     local_ip = get_local_ip()
#     if not local_ip:
#         print("[⚠️] Cannot send alert: local IP unavailable.")
#         return

#     # Always notify main system
#     send_udp(message, MAIN_SYSTEM_IP, port)

#     # Notify specific listener
#     if target_ip:
#         send_udp(message, target_ip, port)
#         return

#     # Broadcast to subnet
#     broadcast_ip = get_broadcast_ip(local_ip)
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             for attempt in range(retries):
#                 sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#                 print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 time.sleep(delay)
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")

# # Optional: test broadcast directly
# if __name__ == "__main__":
#     local_ip = get_local_ip()
#     if local_ip:
#         timestamp = time.strftime("%H:%M:%S")
#         test_message = f"[{timestamp}] Botnet detected on {local_ip}"
#         print(f"[🧪] Sending test broadcast: {test_message}")
#         broadcast_alert(test_message, target_ip=local_ip)
#     else:
#         print("[❌] Skipping broadcast test: no local IP.")



# =================================08-10-25=============================



# import socket
# import logging
# import ipaddress
# import time

# # Setup logging
# log_path = "logs/broadcast_log.txt"
# logging.basicConfig(
#     filename=log_path,
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# MAIN_SYSTEM_IP = "192.168.1.1"  # 🔧 Replace with your actual main system IP

# def get_local_ip():
#     """Detect the active local IP address."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))
#             local_ip = s.getsockname()[0]
#         print(f"[🌐] Local IP detected: {local_ip}")
#         return local_ip
#     except Exception as e:
#         print(f"[❌] Failed to get local IP: {e}")
#         logging.error(f"Failed to get local IP: {e}")
#         return None

# def get_broadcast_ip(local_ip):
#     """Calculate broadcast IP based on local IP and assumed /24 subnet."""
#     try:
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         broadcast_ip = str(network.broadcast_address)
#         print(f"[📡] Calculated broadcast IP: {broadcast_ip}")
#         return broadcast_ip
#     except Exception as e:
#         print(f"[❌] Failed to calculate broadcast IP: {e}")
#         logging.error(f"Failed to calculate broadcast IP: {e}")
#         return "255.255.255.255"

# def send_udp(message, target_ip, port=9999):
#     """Send a UDP message to a specific IP."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.sendto(message.encode("utf-8"), (target_ip, port))
#             print(f"[📨] Alert sent to {target_ip}:{port} → {message}")
#             logging.info(f"Alert sent to {target_ip}:{port} → {message}")
#     except Exception as e:
#         print(f"[❌] Failed to send alert to {target_ip}: {e}")
#         logging.error(f"Failed to send alert to {target_ip}: {e}")

# def broadcast_alert(message, target_ip=None, port=9999, retries=1, delay=0.5):
#     """
#     Send alert to:
#     - Main system (always)
#     - Specific listener (only if target_ip is provided)
#     - Broadcast subnet (only if target_ip is None)
#     """
#     local_ip = get_local_ip()
#     if not local_ip:
#         print("[⚠️] Cannot send alert: local IP unavailable.")
#         return

#     # Always notify main system
#     send_udp(message, MAIN_SYSTEM_IP, port)

#     # If target_ip is provided, send only to that device
#     if target_ip:
#         send_udp(message, target_ip, port)
#         return

#     # Otherwise, broadcast to subnet
#     broadcast_ip = get_broadcast_ip(local_ip)
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             for attempt in range(retries):
#                 sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#                 print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 time.sleep(delay)
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")

# # Optional: test broadcast directly
# if __name__ == "__main__":
#     local_ip = get_local_ip()
#     if local_ip:
#         timestamp = time.strftime("%H:%M:%S")
#         test_message = f"[{timestamp}] Botnet detected on {local_ip}"
#         print(f"[🧪] Sending test alert to local IP only: {test_message}")
#         broadcast_alert(test_message, target_ip=local_ip)
#     else:
#         print("[❌] Skipping test: no local IP.")



# import socket
# import logging
# import ipaddress
# import time

# # Setup logging
# log_path = "logs/broadcast_log.txt"
# logging.basicConfig(
#     filename=log_path,
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s"
# )

# def get_local_ip():
#     """Detect the active local IP address (used as main system IP)."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))
#             local_ip = s.getsockname()[0]
#         print(f"[🌐] Local IP detected: {local_ip}")
#         return local_ip
#     except Exception as e:
#         print(f"[❌] Failed to get local IP: {e}")
#         logging.error(f"Failed to get local IP: {e}")
#         return None

# def get_broadcast_ip(local_ip):
#     """Calculate broadcast IP based on local IP and assumed /24 subnet."""
#     try:
#         network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
#         broadcast_ip = str(network.broadcast_address)
#         print(f"[📡] Calculated broadcast IP: {broadcast_ip}")
#         return broadcast_ip
#     except Exception as e:
#         print(f"[❌] Failed to calculate broadcast IP: {e}")
#         logging.error(f"Failed to calculate broadcast IP: {e}")
#         return "255.255.255.255"

# def send_udp(message, target_ip, port=9999):
#     """Send a UDP message to a specific IP."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.sendto(message.encode("utf-8"), (target_ip, port))
#             print(f"[📨] Alert sent to {target_ip}:{port} → {message}")
#             logging.info(f"Alert sent to {target_ip}:{port} → {message}")
#     except Exception as e:
#         print(f"[❌] Failed to send alert to {target_ip}: {e}")
#         logging.error(f"Failed to send alert to {target_ip}: {e}")

# def broadcast_alert(message, target_ip=None, port=9999, retries=1, delay=0.5):
#     """
#     Send alert to:
#     - Main system (local IP)
#     - Specific listener (only if target_ip is provided)
#     - Broadcast subnet (only if target_ip is None)
#     """
#     local_ip = get_local_ip()
#     if not local_ip:
#         print("[⚠️] Cannot send alert: local IP unavailable.")
#         return

#     # Always notify main system (local IP)
#     send_udp(message, local_ip, port)

#     # If target_ip is provided, send only to that device
#     if target_ip:
#         send_udp(message, target_ip, port)
#         return

#     # Otherwise, broadcast to subnet
#     broadcast_ip = get_broadcast_ip(local_ip)
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
#             sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#             for attempt in range(retries):
#                 sock.sendto(message.encode("utf-8"), (broadcast_ip, port))
#                 print(f"[📢] Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 logging.info(f"Broadcast alert sent to {broadcast_ip}:{port} → {message}")
#                 time.sleep(delay)
#     except Exception as e:
#         print(f"[❌] Broadcast failed: {e}")
#         logging.error(f"Failed to send broadcast alert: {e}")

# # Optional: test broadcast directly
# if __name__ == "__main__":
#     local_ip = get_local_ip()
#     if local_ip:
#         timestamp = time.strftime("%H:%M:%S")
#         test_message = f"[{timestamp}] Botnet detected on {local_ip}"
#         print(f"[🧪] Sending test alert to local IP only: {test_message}")
#         broadcast_alert(test_message, target_ip=local_ip)
#     else:
#         print("[❌] Skipping test: no local IP.")

import socket
import logging
import ipaddress
import time

PORT = 9999
log_path = "logs/broadcast_log.txt"
logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s - %(message)s")

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logging.error(f"Failed to get local IP: {e}")
        return None

def get_broadcast_ip(local_ip):
    try:
        network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        return str(network.broadcast_address)
    except Exception as e:
        logging.error(f"Failed to calculate broadcast IP: {e}")
        return "255.255.255.255"

def send_udp(message, target_ip, port=PORT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode("utf-8"), (target_ip, port))
            print(f"[📨] Alert sent to {target_ip}:{port} → {message}")
            logging.info(f"Alert sent to {target_ip}:{port} → {message}")
    except Exception as e:
        logging.error(f"Failed to send alert to {target_ip}: {e}")

def broadcast_alert(message, target_ip=None, retries=1, delay=0.5):
    """
    Send alert to:
    - Main system (local IP)
    - Specific listener (if target_ip is provided)
    """
    main_ip = get_local_ip()
    if not main_ip:
        print("[⚠️] Cannot send alert: local IP unavailable.")
        return

    # Always notify main system
    send_udp(message, main_ip)

    # Notify specific listener device
    if target_ip and target_ip != main_ip:
        send_udp(message, target_ip)
