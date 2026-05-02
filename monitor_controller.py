"""
Controller CPU monitor — run this in a SEPARATE terminal while controller.py is running.
Finds the controller.py process and prints its CPU + memory usage every 0.1s.
"""

import psutil, time

def find_controller():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'controller.py' in cmdline and 'monitor_controller' not in cmdline:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None

print("Waiting for controller.py process...")
proc = None
while proc is None:
    proc = find_controller()
    if proc is None:
        time.sleep(1)

print(f"Found controller.py (PID {proc.pid}). Monitoring every 0.1s. Ctrl+C to stop.\n")
print(f"{'Time':>8}  {'Controller CPU':>14}  {'Controller MEM':>14}")
print("-" * 42)

proc.cpu_percent()   # first call returns 0 — throw it away

peak_ctrl_cpu = 0.0

try:
    while True:
        time.sleep(0.1)
        try:
            ctrl_cpu = proc.cpu_percent()
            ctrl_mem = proc.memory_info().rss / (1024 * 1024)
            peak_ctrl_cpu = max(peak_ctrl_cpu, ctrl_cpu)
            ts = time.strftime('%H:%M:%S')
            print(f"{ts:>8}  {ctrl_cpu:>13.1f}%  {ctrl_mem:>12.1f}MB")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print("\nController process ended.")
            break
except KeyboardInterrupt:
    print(f"\nPeak controller CPU: {peak_ctrl_cpu:.1f}%")
