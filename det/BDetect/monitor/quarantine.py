# import os

# def block_ip(ip):
#     print(f"[🚫] Blocking IP: {ip}")
#     os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
#     os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=out action=block remoteip={ip}")



# import os
# import socket

# def block_ip(ip):
#     print(f"[🚫] Blocking IP: {ip}")

#     try:
#         gateway = socket.gethostbyname(socket.gethostname())
#         if ip == gateway:
#             print(f"[⚠️] Skipping block — {ip} appears to be your gateway.")
#             return
#     except Exception:
#         pass 

#     os.system(f'netsh advfirewall firewall add rule name="Block_In_{ip}" dir=in action=block remoteip={ip}')
#     os.system(f'netsh advfirewall firewall add rule name="Block_Out_{ip}" dir=out action=block remoteip={ip}')




# import os
# import socket

# def get_gateway_ip():
#     try:
#         output = os.popen("ipconfig").read()
#         for line in output.splitlines():
#             if "Default Gateway" in line:
#                 parts = line.split(":")
#                 if len(parts) > 1:
#                     return parts[1].strip()
#     except Exception:
#         return None

# def block_ip(ip):
#     gateway = get_gateway_ip()
#     local_ip = socket.gethostbyname(socket.gethostname())

#     # Safety checks
#     if ip in [gateway, local_ip]:
#         print(f"[⚠️] Skipping block — {ip} is gateway or local IP.")
#         return

#     print(f"[🚫] Blocking IP: {ip}")
#     os.system(f'netsh advfirewall firewall add rule name="Block_In_{ip}" dir=in action=block remoteip={ip}')
#     os.system(f'netsh advfirewall firewall add rule name="Block_Out_{ip}" dir=out action=block remoteip={ip}')
