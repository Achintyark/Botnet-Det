import os

def load_recent_file_transfers(limit=10):
    path = "data/file_transfer_log.csv"
    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
        return [line.strip().split(",") for line in lines]

def render_file_transfer_panel():
    entries = load_recent_file_transfers()
    print("\n📁 Recent File Transfers")
    print("-" * 40)
    for timestamp, ip, summary in entries:
        print(f"[{timestamp}] {ip} → {summary}")
