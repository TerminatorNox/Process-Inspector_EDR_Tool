import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import psutil
import subprocess
import threading
import time
import os
import hashlib
from collections import deque
from queue import Queue

# ================= CONFIG =================
UPDATE_INTERVAL = 1.5
SUSPICIOUS_STRINGS = [
    b"http://", b"https://", b".exe", b"powershell",
    b"cmd.exe", b"/bin/bash", b"/bin/sh"
]

# ================= PLATFORM SELECTOR =================
class PlatformSelector:
    def __init__(self):
        self.platform = None
        self.root = ctk.CTk()
        self.root.title("Select Platform")
        self.root.geometry("400x220")

        ctk.CTkLabel(self.root, text="Select Running Platform", font=("Consolas", 20, "bold")).pack(pady=20)
        ctk.CTkButton(self.root, text="🪟 Windows", command=lambda: self.select("windows"), width=200).pack(pady=10)
        ctk.CTkButton(self.root, text="🍎 macOS", command=lambda: self.select("mac"), width=200).pack(pady=10)

        self.root.mainloop()

    def select(self, platform):
        self.platform = platform
        self.root.destroy()

# ================= MAIN EDR =================
class CyberPulseEDR:
    def __init__(self, platform):
        self.platform = platform
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title(f"CYBER‑PULSE EDR ({platform.upper()})")
        self.root.geometry("1400x900")

        self.running_process = None
        self.monitoring = False
        self.last_net = psutil.net_io_counters()
        self.last_time = time.time()
        self.log_queue = Queue()

        self.build_ui()
        self.process_log_queue()

    # ================= UI =================
    def build_ui(self):
        ctk.CTkLabel(self.root, text="CYBER‑PULSE | Advanced EDR", font=("Consolas", 26, "bold")).pack(pady=10)

        bar = ctk.CTkFrame(self.root)
        bar.pack(fill="x", padx=20)

        self.path_var = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=self.path_var, width=600).pack(side="left", padx=10)
        ctk.CTkButton(bar, text="Browse", command=self.browse).pack(side="left")
        ctk.CTkButton(bar, text="Start", command=self.start).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Scan Memory", command=self.scan_memory).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Dump & Hash", command=self.dump_and_hash).pack(side="left", padx=5)

        # Live Metrics Text
        metrics_frame = ctk.CTkFrame(self.root)
        metrics_frame.pack(fill="x", padx=20, pady=10)
        self.cpu_label = ctk.CTkLabel(metrics_frame, text="CPU: --- %", font=("Consolas", 14))
        self.cpu_label.pack(side="left", padx=20)
        self.mem_label = ctk.CTkLabel(metrics_frame, text="RAM: --- MB", font=("Consolas", 14))
        self.mem_label.pack(side="left", padx=20)
        self.net_label = ctk.CTkLabel(metrics_frame, text="Net: --- KB/s", font=("Consolas", 14))
        self.net_label.pack(side="left", padx=20)

        self.log_box = tk.Text(self.root, bg="#0b0e14", fg="#58a6ff", height=20)
        self.log_box.pack(fill="both", expand=True, padx=20, pady=10)

    # ================= LOG =================
    def log(self, msg):
        self.log_queue.put(f"{time.ctime()} | {msg}")

    def process_log_queue(self):
        while not self.log_queue.empty():
            self.log_box.insert("end", self.log_queue.get() + "\n")
            self.log_box.see("end")
        self.root.after(500, self.process_log_queue)

    # ================= FILE =================
    def browse(self):
        f = filedialog.askopenfilename()
        if f:
            self.path_var.set(f)

    # ================= START =================
    def start(self):
        target = self.path_var.get()
        if not os.path.exists(target):
            messagebox.showerror("Error", "Invalid target")
            return
        try:
            if self.platform == "windows":
                proc = subprocess.Popen([target])
            else:
                proc = subprocess.Popen(["open", target])
            self.running_process = psutil.Process(proc.pid)
            self.running_process.cpu_percent(None)
            self.monitoring = True
            self.log(f"Monitoring PID {proc.pid}")
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Launch Error", str(e))

    # ================= MONITOR =================
    def monitor_loop(self):
        while self.monitoring:
            try:
                p = self.running_process
                cpu = p.cpu_percent(interval=0.1)
                mem = p.memory_info().rss / 1024 / 1024
                now = time.time()
                net_now = psutil.net_io_counters()
                net = (net_now.bytes_sent + net_now.bytes_recv - self.last_net.bytes_sent - self.last_net.bytes_recv)/1024/max(now - self.last_time,0.1)
                self.last_net = net_now
                self.last_time = now
                # Update live text
                self.root.after(0, lambda: self.cpu_label.configure(text=f"CPU: {cpu:.1f}%"))
                self.root.after(0, lambda: self.mem_label.configure(text=f"RAM: {mem:.1f} MB"))
                self.root.after(0, lambda: self.net_label.configure(text=f"Net: {net:.1f} KB/s"))
                time.sleep(UPDATE_INTERVAL)
            except (psutil.ZombieProcess, psutil.NoSuchProcess):
                self.log("Process exited or zombie")
                self.monitoring = False
                break
            except Exception as e:
                self.log(f"Monitor error: {e}")
                time.sleep(UPDATE_INTERVAL)

    # ================= MEMORY STRING SCAN =================
    def scan_memory(self):
        if not self.running_process: return
        win = ctk.CTkToplevel(self.root)
        win.title("Memory String Scanner")
        win.geometry("800x450")
        text = tk.Text(win, bg="#0b0e14", fg="#3fb950")
        text.pack(fill="both", expand=True)

        def scan():
            try:
                exe = self.running_process.exe()
                with open(exe,"rb") as f: data=f.read()
                found = set(s.decode(errors="ignore") for s in SUSPICIOUS_STRINGS if s in data)
                self.root.after(0, lambda: text.insert("end","Suspicious Strings Found:\n\n" + ("\n".join(found) if found else "None detected")))
            except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
                self.root.after(0, lambda: text.insert("end",f"Cannot scan PID {self.running_process.pid} — zombie or inaccessible"))
            except Exception as e:
                self.root.after(0, lambda: text.insert("end",f"Scan failed: {e}"))

        threading.Thread(target=scan,daemon=True).start()

    # ================= DUMP & HASH =================
    def dump_and_hash(self):
        if not self.running_process: return
        win = ctk.CTkToplevel(self.root)
        win.title("Process Dump & Hash")
        win.geometry("700x350")
        text = tk.Text(win,bg="#0b0e14",fg="#58a6ff")
        text.pack(fill="both", expand=True)

        try:
            exe = self.running_process.exe()
            sha = hashlib.sha256()
            with open(exe,"rb") as f:
                for chunk in iter(lambda:f.read(8192),b""): sha.update(chunk)
            text.insert("end",f"Executable Path:\n{exe}\n\nSHA256:\n{sha.hexdigest()}\n\n")
            if self.platform=="windows":
                text.insert("end","Mini dump: User-space only\n")
            else:
                text.insert("end","macOS: Executable hash only (no memory dump)\n")
        except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
            text.insert("end",f"Cannot access PID {self.running_process.pid} — zombie or inaccessible")
        except Exception as e:
            text.insert("end",f"Failed: {e}")

    # ================= RUN =================
    def run(self):
        self.root.mainloop()

# ================= ENTRY =================
if __name__=="__main__":
    selector = PlatformSelector()
    CyberPulseEDR(selector.platform).run()
