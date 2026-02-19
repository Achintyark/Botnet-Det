import subprocess

def run_remote_scan(ip, tool_path="C:\\Path\\To\\Scanner.exe"):
    try:
        print(f"[🛡️] Triggering remote scan on {ip}...")
        subprocess.run([
            "psexec", f"\\\\{ip}", "cmd", "/c", tool_path
        ], check=True)
        print(f"[✅] Remote scan triggered on {ip}.")
    except Exception as e:
        print(f"[❌] Remote scan failed: {e}")
