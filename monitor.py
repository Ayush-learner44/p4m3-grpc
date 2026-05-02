from scapy.all import sniff, IPv6, TCP
import sys, os, threading, psutil

stats = {'syn': 0, 'other': 0, 'cpu': 0.0, 'peak_cpu': 0.0}

iface = "h2-eth0"
os.system(f"ip link set {iface} up")

def cpu_sampler():
    while True:
        cpu = psutil.cpu_percent(interval=1)
        stats['cpu'] = cpu
        if cpu > stats['peak_cpu']:
            stats['peak_cpu'] = cpu

def process_pkt(pkt):
    if pkt.haslayer(IPv6) and pkt.haslayer(TCP) and (pkt[TCP].flags & 0x02):
        stats['syn'] += 1
    else:
        stats['other'] += 1
    sys.stdout.write(
        f"\r[h2] SYN:{stats['syn']}  Other:{stats['other']}  "
        f"|  CPU:{stats['cpu']:.1f}%  Peak:{stats['peak_cpu']:.1f}%   "
    )
    sys.stdout.flush()

threading.Thread(target=cpu_sampler, daemon=True).start()

print(f"Monitor started on {iface}. Watching packets + CPU. Ctrl+C to stop.")
sniff(iface=iface, prn=process_pkt, store=0)
