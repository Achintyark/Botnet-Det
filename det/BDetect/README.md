Streamlit --- Web UI framework for data apps.
          --- Build the app UI (widgets, displays) and serve as front-end.
          --- Any machine with Python and Streamlit installed; users view via browser.

streamlit_autorefresh.st_autorefresh  --- Helper to auto-refresh Streamlit pages periodically.
                                      --- Poll for new data or refresh UI automatically.
                                      --- Inside Streamlit app code.
                                      --- Use when you want periodic UI refresh; be careful with heavy backend work on refresh.

pandas --- Dataframes and data manipulation.
       --- For tabular data, CSV/Excel I/O, preparing tables to show in Streamlit.
       --- Any Python environment.
       --- When processing logs/csvs or presenting tables.

re (regular expressions) --- Regex parsing.
                         --- Parse text fields from packet payloads, log lines, extract patterns.
                         --- Parsing, validation tasks.

datetime, timedelta --- Date/time handling.
                    --- Timestamp logs, compute time windows, timers for alerts.
                    --- Anywhere you need time math.

manuf (from manuf import manuf) --- python-manuf - MAC address vendor lookup lib
                                --- Map MAC prefixes to vendor names (for discovered devices).
                                --- Works offline with its vendor DB; install via pip install python-manuf.
                                --- After you extract a MAC from packets or ARP/NDP, call the parser to get vendor.

scapy (scapy.all as scapy, from scapy.all import sniff, TCP, Raw, IP, DNSQR, conf) --- 
                                  ----- Packet crafting/capture/analysis library.
                                  ----- Inspect raw packets, build/modify network packets, sniff traffic.
                                  ----- Best on Linux/macOS; on Windows limited and requires npcap/winpcap. Needs root/admin for sniffing.
                                  ----- Use for custom packet capture or active network tests. Do not run in Streamlit main thread; spawn a thread or separate process. Be aware of security/legal issues capturing traffic.

pyshark --- Python wrapper for tshark (Wireshark CLI).
        --- High-level packet parsing using tshark dissectors.
        --- Requires tshark installed on the machine (Wireshark package)
        --- Use if you want tshark parsing power; must call subprocess or pyshark capture. Also needs admin privileges for live capture.

socket,ipaddress --- Network sockets and IP address utilities.
                 --- Hostname lookups, IP validation, local interface checks
                 --- Network utilities, binding sockets, solving network logic.

requests --- HTTP client.
         --- Query APIs, post alerts to external services.
         --- Any HTTP interactions. Use timeouts and exception handling.

psutil --- System / process info (CPU, memory, network counters).
       --- Monitor system resources for thresholds (e.g., detect heavy CPU during capture).
       --- For resource monitoring and alerts.

matplotlib (plt) --- Plotting library.
                 --- Create charts to display in Streamlit (st.pyplot()).
                 --- Visualizing metrics, but heavy plotting on each refresh can be slow.

numpy (np) --- Numeric arrays and operations.   
           --- Preprocessing images, converting arrays for PyTorch/OpenCV.
           --- Image transforms, numeric computations.

Pillow (from PIL import Image) --- Image I/O and processing.
                               --- Load images for model inference, display.
                               --- Use with torchvision transforms or OpenCV (convert between formats).

OpenCV (cv2) --- Computer vision library with many optimized ops
             --- Video capture, image pre/post-processing, contours, frame manipulation.
             --- Needs opencv-python wheel; certain features need extra binaries.
             --- When you need CV primitives or real-time video processing.

PyTorch (torch, torch.nn, torchvision.transforms, torch.optim, DataLoader, etc.) ------ Deep learning framework.
                          ------------ Define and run BotnetCNN model inference/training.
                          ------------ Works CPU-only, but GPU acceleration requires CUDA and matching PyTorch build.
                          ------------ Load model once (preferably in a singleton), run inference on incoming data. Loading large models should be done in background or cached.

torchvision --- Datasets, models, and transforms for vision.
            --- To transform images for model input (resize, normalize).
            --- During preprocessing pipeline before feeding to BotnetCNN.

yagmail --- Gmail sending helper.
        --- Send email alerts via Gmail.
        --- For alert notifications; be careful storing credentials (use env vars / OAuth).

plyer (from plyer import notification) --- Cross-platform desktop notifications.
                                       --- Show desktop pop-ups when an alert occurs.
                                       --- Works on many desktop OSes. On some Linux desktops, additional notification daemon needed; on Windows requires no extra install
                                       --- Use on local desktop apps; it will not work in headless servers or Streamlit cloud without a desktop environment.

ctypes --- Low-level C calls (Windows MessageBox or other OS calls).        
       --- Show native OS dialogs or call kernel functions.
       --- Windows-specific UI actions — guard with if platform.system() == "Windows".

logging --- Standard logging.
        --- Structured logs instead of print(); easier debugging and audit trail.
        --- Always use logging in production code.

matplotlib.pyplot --- Avoid blocking interactive plotting in Streamlit. Use st.pyplot().





os → Lets your Python code work with files, folders, and system paths.

sys → Controls Python itself (like command-line args, exit, or import paths).

subprocess → Runs other programs or system commands from Python.

time → Handles delays, timestamps, and time calculations.

threading → Runs multiple tasks at the same time (parallel execution).

json → Reads and writes data in JSON (key–value) format.

logging → Records events or messages for debugging and tracking.
                                                                                                                                                                                                    
                                                                                                                             BDetect  
|
| --- capture
|        | -- capture_traffic.py
|        | -- scan_wifi.py
| --- config
|        | -- email_config.json
|        | -- malicious_domains.txt
|        | -- thresholds.json
| --- data
|        | -- images
|               | - benign/
|               | - botnet/
|        | -- pcap/
|        | -- domain_alerts.csv
|        | -- file_transfer_log.csv
|        | -- prediction_log.csv
|        | -- results.csv
|        | -- scan_log.csv
| --- logs
|        | -- broadcast_log.txt
| --- model
|        | -- explain_prediction.py
|        | -- inference.py
|        | -- model.pth
|        | -- train_model.py
|        | -- train_pipeline.py
| --- monitor
|        | -- alert_admin.py
|        | -- broadcast_alert.py
|        | -- domain_reputation.py
|        | -- domain_watch.py
|        | -- file_transfer_watch.py
|        | -- notify_devices.py
|        | -- push_alerts.py
|        | -- quarantine.py (optional)
|        | -- realtime_loop.py
|        | -- scan_local.py
|        | -- shutdown_network.py (optional)
| --- preprocess 
|        | -- convert_pcap_to_png.py (imp)
| --- broadcast_log.txt       
| --- dashboard.py (UI)
| --- main.py (entry point)
| --- plot_dashboard.py (training pcap files converted into png(image or QR))
| --- README.md (information)
| --- requirements.txt
| --- train_model.py(train our png test file )
| 


--------> capture_traffic.py <-------- captures live network packets from a specific device IP for a fixed duration using Scapy. It saves the traffic as a .pcap file, which is later used for botnet behavior analysis and image conversion. This file is key to detecting suspicious activity like uploads, downloads, or domain access from any device.

--------> scan_wifi.py <--------  scans your local network to discover all connected devices using ARP and ping sweeps. It collects each device's IP and MAC address, helping your system identify new arrivals and monitor their activity. This file is essential for real-time device discovery and enrichment.

--------> domain_alerts.csv <--------  is your live log file that records every domain accessed by devices on your network. It stores the timestamp, domain name, source IP, and VirusTotal verdict (e.g., clean, suspicious, malicious). This file is crucial for auditing, alerting, and visualizing domain reputation activity across your system.

--------> file_transfer_log.csv <-------- records every detected upload or download attempt by devices on your network. It logs the timestamp, source IP, destination IP, file direction (upload/download), and protocol used. This file is vital for tracking suspicious file movements and triggering real-time alerts.

--------> prediction_log.csv <--------  stores the classification results for each device traffic capture. It logs the timestamp, device IP, model confidence score, and predicted label (e.g., benign or suspicious). This file is essential for tracking botnet detection outcomes and triggering alerts based on model verdicts.

--------> broadcast_log.txt <--------  ecords every broadcast alert sent across your network, such as botnet detections or file transfer warnings. It logs the timestamp, target broadcast IP, port, and alert message. This file is essential for verifying that all listener devices received real-time notifications.

--------> explain_prediction.py <-------- analyzes the model's classification output for a device's traffic and explains why it was labeled as benign or suspicious. It highlights key features or patterns from the .pcap file or image that influenced the decision. This file is crucial for transparency, debugging, and teaching how your botnet detection model works.


--------> inference.py <--------  runs your trained classification model on captured traffic data (usually converted images from .pcap files). It outputs a confidence score and a label (benign or suspicious), which gets logged and used to trigger alerts. This file is the core decision engine of your botnet detection system.

--------> model.pth <--------  is your saved PyTorch model file containing the trained weights and architecture for botnet traffic classification. It’s loaded during inference to predict whether captured device behavior is benign or suspicious. This file powers the core intelligence behind your alert system.

--------> train_model.py <--------  trains your botnet classification model using labeled traffic data converted into images. It defines the neural network architecture, loss function, optimizer, and training loop, then saves the learned weights to model.pth. This file is the foundation for building accurate predictions during inference


--------> train_pipeline.py <-------- orchestrates the full training workflow for your botnet detection model. It loads datasets, preprocesses traffic images, trains the model, evaluates performance, and saves the final weights to model.pth. This file streamlines the entire training process into a single, reproducible pipeline.


--------> alert_admin.py <--------  handles all alerting logic when suspicious activity is detected. It sends notifications via email, broadcast UDP, Telegram, and popup messages to ensure admins and listener devices are instantly informed. This file is critical for real-time response and network-wide awareness.

--------> broadcast_alert.py <--------  sends UDP broadcast messages across your local network to notify all listener devices of suspicious activity. It includes the alert type, source IP, and context (e.g., domain access or file transfer). This file ensures network-wide visibility and instant response coordination.

--------> domain_reputation.py <--------  checks the safety of accessed domains using the VirusTotal API. It sends each domain for analysis, retrieves the verdict (clean/suspicious/malicious), and caches results to avoid redundant lookups. This file powers your real-time domain alerts and enriches logs with reputation data.

--------> domain_watch.py <--------  monitors live DNS traffic from devices on your network, extracting accessed domain names in real time. It logs each domain with timestamp and source IP, then triggers reputation checks and alerts if needed. This file is the frontline sensor for detecting suspicious domain activity.

--------> file_transfer_watch.py <--------  monitors live network traffic to detect upload and download attempts by any device. It parses packet flows, identifies file transfer patterns, logs them to file_transfer_log.csv, and triggers alerts if needed. This file is key to catching suspicious data exfiltration or inbound payloads in real time

--------> notify_devices.py <-------- sends targeted alerts to specific devices (not broadcast-wide) using IP-based delivery. It supports multiple channels like email, Telegram, and popups, ensuring each device gets personalized warnings. This file is key for direct, device-specific notifications in your alerting system.

--------> push_alerts.py <--------  coordinates all alert delivery across your system. It pulls verdicts from logs (domain, file, prediction), formats alert messages, and triggers multi-channel notifications via broadcast, email, Telegram, and popups. This file ensures every detection leads to timely, actionable alerts.

--------> quarantine.py <--------  isolates suspicious devices by applying firewall rules that block all inbound and outbound traffic. It uses the device’s IP and MAC address to enforce containment and logs the action for audit. This file is critical for stopping potential threats instantly and safely.

--------> realtime_loop.py <--------  is the heartbeat of your botnet detection system. It continuously runs all monitoring threads — domain watch, file transfer watch, prediction, reputation check, and alerting — in parallel. This file ensures your entire pipeline operates live, synchronized, and responsive to threats as they happen.

--------> scan_local.py <--------  performs a focused scan of your local subnet to identify active devices using ARP and ping. It’s optimized for speed and reliability, even when some devices block ping. This file is essential for populating your dashboard with real-time device presence and MAC/vendor enrichment.

--------> shutdown_network.py <--------  forcefully disables network access for all devices by applying global firewall rules or disabling key interfaces. It’s a last-resort containment tool used during critical threats or demo resets. This file ensures total lockdown to halt all traffic instantly across the system.
 

--------> convert_pcap_to_png.py <--------  transforms raw .pcap files into image representations suitable for deep learning. It parses packet data, extracts byte-level features, and converts each flow or session into a grayscale or RGB image. These images are saved for training your botnet classifier, enabling visual pattern recognition from network traffic.

--------> dashboard.py <--------  powers your interactive threat visibility panel. It displays real-time alerts from domain, file, and botnet monitors, shows device status (IP, MAC, vendor), and visualizes reputation verdicts, file transfers, and quarantine actions. It includes scan triggers, log viewers, and alert history — making your system teachable, transparent, and actionable.

--------> main.py <--------  is your system’s launchpad. It initializes all core modules — scanning, monitoring, prediction, alerting, dashboard — and starts the realtime_loop.py to keep everything running live. This file ties together your botnet detection pipeline, ensuring synchronized startup, thread visibility, and full system activation.

--------> requirements.txt <--------  lists all the Python dependencies your botnet detection system needs to run. It ensures consistent environments across machines and simplifies setup.





<!-- What "0/24" means:
0 (Starting Address): This is the network address. It's the first address in the IP range. 
/24 (Prefix Length): This signifies that the first 24 bits of the 32-bit IPv4 address are fixed for the network portion. 
Host Portion: The remaining 32 - 24 = 8 bits are used for the host addresses within that network. 
Calculating the range:
Total Addresses: With 8 bits for hosts, you have 2^8 = 256 possible addresses. 
Network Address: The first address in the range is 0.0.0.0, which is reserved for the network. 
Broadcast Address: The last address is 0.0.0.255, which is used for broadcasting and is also reserved. 
Usable Host Addresses: This leaves 254 usable addresses for devices on the network, from 0.0.0.1 to 0.0.0.254 -->