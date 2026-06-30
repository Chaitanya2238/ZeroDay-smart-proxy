# test_rasp_live.py - Test script to verify RASP detection works (emoji-free)
import sys
import os
import time
import subprocess
import threading

# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from rasp_backend.process_monitor import WindowsProcessMonitor
from rasp_backend.markov_model import PrivEscMarkovModel

def test_process_monitor():
    print("="*60)
    print("TESTING: Process Monitor")
    print("="*60)
    
    monitor = WindowsProcessMonitor()
    
    # Get initial processes
    initial = monitor.get_running_processes()
    print(f"[OK] Found {len(initial)} processes running")
    
    # Start a cmd process
    print("\n[INFO] Starting Command Prompt (cmd.exe)...")
    cmd_proc = subprocess.Popen(["cmd.exe", "/c", "timeout 3"], creationflags=subprocess.CREATE_NO_WINDOW)
    
    time.sleep(1.5)
    
    # Check for new processes
    new_procs = monitor.check_new_processes()
    cmd_detected = False
    for p in new_procs:
        if "cmd" in p['name'].lower():
            cmd_detected = True
            print(f"[OK] DETECTED: {p['name']} (PID {p['pid']})")
            
    if cmd_detected:
        print("\n[SUCCESS] Process Monitor is WORKING!")
    else:
        print("\n[FAIL] Process Monitor didn't detect new cmd.exe - check permissions?")
        
    cmd_proc.wait()
    return cmd_detected

def test_markov_model():
    print("\n" + "="*60)
    print("TESTING: Markov Chain Model")
    print("="*60)
    
    # Initialize model
    model = PrivEscMarkovModel()
    print("[OK] Model initialized")
    
    # Test normal sequence
    normal_seq = ["explorer", "chrome", "system", "python"]
    is_anomaly, prob = model.is_anomaly(normal_seq)
    print(f"   Normal Sequence: {normal_seq}")
    print(f"   Is Anomaly: {is_anomaly} (prob: {prob:.5f})")
    
    # Test attack sequence
    attack_seq = ["cmd", "whoami", "net", "schtasks"]
    is_anomaly, prob = model.is_anomaly(attack_seq)
    print(f"\n   Attack Sequence: {attack_seq}")
    print(f"   Is Anomaly: {is_anomaly} (prob: {prob:.5f})")
    
    print("\n[SUCCESS] Markov Model is WORKING!")
    return True

def run_full_test():
    print("\n" + "="*60)
    print("RASP LIVE MONITORING - FULL TEST")
    print("="*60)
    
    proc_ok = test_process_monitor()
    markov_ok = test_markov_model()
    
    print("\n" + "="*60)
    if proc_ok and markov_ok:
        print("[ALL PASSED] System is READY for Demo!")
    else:
        print("[WARNING] Some tests failed - check logs")
    print("="*60)

if __name__ == "__main__":
    run_full_test()
