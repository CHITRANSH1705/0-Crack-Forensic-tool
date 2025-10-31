import os
import platform
import psutil
import socket
import getpass
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from cryptography.fernet import Fernet
import subprocess
import sqlite3
import shutil
import json

# ---------------------------
# CONFIG
# ---------------------------
MY_PASSWORD = "Chitransh@123"
ENCRYPTED_FILE = "advanced_forensic_report.enc"
KEY_FILE = "forensic_key.key"

# Generate key only if not exists
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# ---------------------------
# HELPER FUNCTIONS (System, Processes, Network, etc.)
# ---------------------------
def get_system_info():
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk = psutil.disk_partitions()
    users = [u.name for u in psutil.users()]
    return {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.machine(),
        "Hostname": socket.gethostname(),
        "Current User": getpass.getuser(),
        "Boot Time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "CPU Cores": psutil.cpu_count(logical=False),
        "Logical CPUs": psutil.cpu_count(),
        "CPU Frequency (MHz)": f"{cpu_freq.current:.2f}" if cpu_freq else "N/A",
        "Total RAM (GB)": f"{mem.total / (1024**3):.2f}",
        "Used RAM (GB)": f"{mem.used / (1024**3):.2f}",
        "Disk Partitions": [f"{p.device} - {p.mountpoint} ({p.fstype})" for p in disk],
        "Logged-in Users": users
    }

def get_process_info():
    processes = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent", "username"]):
        info = proc.info
        try:
            path = psutil.Process(info['pid']).exe()
            if 'temp' in path.lower() or 'appdata' in path.lower():
                info['alert'] = True
            else:
                info['alert'] = False
        except:
            info['alert'] = False
        processes.append(info)
    processes.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
    return processes[:10]

def get_network_info():
    connections = []
    adapters = []
    for conn in psutil.net_connections(kind="inet"):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        connections.append({"pid": conn.pid, "local": laddr, "remote": raddr, "status": conn.status})
    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            adapters.append(f"{nic} - {addr.address} ({addr.family})")
    return connections[:10], adapters

def get_usb_info():
    devices = []
    try:
        if platform.system() == "Windows":
            with os.popen("wmic path Win32_USBHub get DeviceID, Description") as f:
                devices = [line.strip() for line in f.readlines()[1:] if line.strip()]
        else:
            devices = os.popen("lsusb").read().splitlines()
    except:
        devices.append("USB info not available")
    return devices

def get_drives():
    drives = []
    for part in psutil.disk_partitions():
        drives.append(f"{part.device} mounted at {part.mountpoint} ({part.fstype})")
    return drives

def get_recent_files(hours=48):
    recent_files = []
    now = datetime.datetime.now()
    paths = [os.path.expanduser("~/Desktop"), os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads")]
    for path in paths:
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    full_path = os.path.join(root, f)
                    mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
                    if (now - mtime).total_seconds() < hours * 3600:
                        recent_files.append(f"{full_path} (Modified: {mtime})")
                except:
                    continue
    return recent_files[:20]

def get_browser_history():
    history = []
    try:
        browsers = {
            "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"),
            "Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"),
        }
        for name, path in browsers.items():
            if os.path.exists(path):
                tmp_path = path + "_tmp"
                shutil.copy2(path, tmp_path)
                conn = sqlite3.connect(tmp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20")
                rows = cursor.fetchall()
                for r in rows:
                    history.append(f"{name}: {r[1]} - {r[0]}")
                conn.close()
                os.remove(tmp_path)
    except:
        history.append("Browser history not available")
    return history

def get_startup_tasks():
    tasks = []
    try:
        if platform.system() == "Windows":
            output = subprocess.getoutput("schtasks /query /fo LIST /v")
            tasks = [line for line in output.splitlines() if line.strip()][:20]
        else:
            tasks = os.popen("crontab -l").read().splitlines()[:20]
    except:
        tasks.append("Startup tasks not available")
    return tasks

def get_shutdown_logs():
    logs = []
    try:
        if platform.system() == "Windows":
            logs = os.popen("wevtutil qe System /q:*[System[(EventID=1074)]] /c:5 /f:text").read().splitlines()
        else:
            logs = os.popen("last -n 5").read().splitlines()
    except:
        logs.append("Shutdown log not available")
    return logs

# ---------------------------
# GUI
# ---------------------------
def show_gui_report(report_data):
    root = tk.Tk()
    root.title("Forensic Report Viewer")
    root.geometry("1000x700")
    tab_control = ttk.Notebook(root)

    for section, content in report_data.items():
        tab = ttk.Frame(tab_control)
        tab_control.add(tab, text=section)
        text_area = scrolledtext.ScrolledText(tab, wrap=tk.WORD, width=120, height=40)
        text_area.pack(fill=tk.BOTH, expand=True)
        if isinstance(content, list):
            text_area.insert(tk.END, "\n".join([str(i) for i in content]))
        elif isinstance(content, dict):
            for k, v in content.items():
                text_area.insert(tk.END, f"{k}: {v}\n")
        else:
            text_area.insert(tk.END, str(content))
        text_area.configure(state="disabled")
    tab_control.pack(expand=1, fill="both")
    root.mainloop()

# ---------------------------
# ENCRYPT REPORT
# ---------------------------
def encrypt_report(data):
    encrypted_data = cipher.encrypt(json.dumps(data).encode())
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_data)
    print(f"[+] Report encrypted and saved as {ENCRYPTED_FILE}")

# ---------------------------
# MAIN
# ---------------------------
def main():
    report_data = {
        "System Info": get_system_info(),
        "Top Processes": get_process_info(),
        "Network Connections": get_network_info()[0],
        "Network Adapters": get_network_info()[1],
        "USB & Devices": get_usb_info(),
        "Drives": get_drives(),
        "Recent Files": get_recent_files(),
        "Browser History": get_browser_history(),
        "Startup & Scheduled Tasks": get_startup_tasks(),
        "Shutdown Logs": get_shutdown_logs()
    }

    show_gui_report(report_data)
    encrypt_report(report_data)

if __name__ == "__main__":
    main()
