
#!/usr/bin/env python3
# Test script to verify RASP monitoring setup

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rasp_backend.process_monitor import WindowsProcessMonitor

print("Testing Windows Process Monitor...")

monitor = WindowsProcessMonitor()
print("1. Initial check_new_processes()...")
result1 = monitor.check_new_processes()
print(f"   Returned: {len(result1)} new processes")
print(f"   Initialized? {monitor.initialized}")
print()

print("2. Let's see some running processes...")
all_procs = monitor.get_running_processes()
print(f"   Total running: {len(all_procs)}")
print("   First 10 processes:")
for proc in all_procs[:10]:
    print(f"   - {proc['name']} (PID {proc['pid']}) - Safe? {monitor.is_safe_process(proc['name'])}")
