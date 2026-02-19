# import subprocess

# def run_windows_defender_scan():
#     try:
#         print("[*]Starting full system scn with windows Defender...")
#         subprocess.run([r"%ProgramFiles%\Windows Defender\MpCmdRun.exe","-Scan","-ScanType","2"],check=True)
#         print("Scan completed successfully.")
#     except Exception as e:
#         print(f"Scan failer:{e}")    




import subprocess

def run_windows_defender_scan():
    subprocess.run([
        r"%ProgramFiles%\Windows Defender\MpCmdRun.exe",
        "-Scan", "-ScanType", "2"
    ], check=True)
