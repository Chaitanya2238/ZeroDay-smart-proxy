# rasp_backend/process_monitor.py
import subprocess
import os
import time
from collections import deque
import threading
from datetime import datetime

class WindowsProcessMonitor:
    def __init__(self, max_history=20):
        self.max_history = max_history
        self.process_history = deque(maxlen=max_history)
        self.lock = threading.Lock()
        self.pid_cache = set()
        self.initialized = False  # Track if we've done initial load
        
        # Suspect process names for privilege escalation
        self.suspect_processes = [
            "cmd", "cmd.exe",
            "powershell", "powershell.exe", "pwsh", "pwsh.exe",
            "whoami", "whoami.exe",
            "net", "net.exe",
            "schtasks", "schtasks.exe",
            "sc", "sc.exe",
            "reg", "reg.exe",
            "systeminfo", "systeminfo.exe",
            "tasklist", "tasklist.exe",
            "rundll32", "rundll32.exe",
            "wmic", "wmic.exe",
            "mshta", "mshta.exe"
        ]
        
        # Known safe Windows processes to automatically ignore
        self.known_safe_processes = [
            "Registry", "System", "svchost.exe", "explorer.exe",
            "csrss.exe", "wininit.exe", "winlogon.exe",
            "dwm.exe", "fontdrvhost.exe", "smss.exe",
            "spoolsv.exe", "lsass.exe", "services.exe",
            "chrome.exe", "firefox.exe", "msedge.exe"
        ]
    
    def is_safe_process(self, proc_name):
        """Check if a process is known safe"""
        proc_lower = proc_name.lower()
        for safe in self.known_safe_processes:
            if safe.lower() in proc_lower:
                return True
        return False

    def get_running_processes(self):
        """Get running process details using tasklist"""
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5
            )
            processes = []
            for line in result.stdout.strip().splitlines():
                parts = line.split('","')
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    pid = parts[1].strip('"')
                    processes.append({
                        "pid": pid,
                        "name": name,
                        "timestamp": datetime.now().isoformat()
                    })
            return processes
        except Exception as e:
            print(f"Process check error: {e}")
            return []

    def check_new_processes(self):
        """Check for new processes and update history"""
        new_procs = self.get_running_processes()
        new_pids = {p['pid'] for p in new_procs}
        
        # Find newly spawned processes
        with self.lock:
            if not self.initialized:
                # First run - just load all processes into cache, no detections
                self.pid_cache = new_pids
                self.initialized = True
                print(f"Process monitor initialized, found {len(new_procs)} running processes")
                return []
            
            current_pids = self.pid_cache
            spawned_pids = new_pids - current_pids
            self.pid_cache = new_pids
            
            # Add newly spawned to history
            spawned_procs = [p for p in new_procs if p['pid'] in spawned_pids and not self.is_safe_process(p['name'])]
            for proc in spawned_procs:
                self.process_history.append(proc)
            
            return spawned_procs

    def get_recent_process_names(self, count=5):
        """Get list of recent process names only"""
        with self.lock:
            return [p['name'] for p in list(self.process_history)[-count:]]

    def get_full_history(self):
        """Get full process history"""
        with self.lock:
            return list(self.process_history)

# Singleton instance
_monitor_instance = None
def get_monitor():
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = WindowsProcessMonitor()
    return _monitor_instance
