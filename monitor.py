from scapy.all import sniff, IPv6, TCP
import sys, os, threading, psutil, signal

ATTACKER_IPS = {"2001:1:1::1", "2001:1:1::2", "2001:1:1::3"}
LEGIT_IPS    = {"2001:3:1::1", "2001:3:1::2", "2001:3:1::3"}

TOTAL_ATTACK_SENT = 600
TOTAL_LEGIT_SENT  = 180

stats = {
    'syn': 0, 'other': 0,
    'cpu': 0.0, 'peak_cpu': 0.0,
    'attack_reached': 0,
    'legit_reached':  0,
}

iface = "h2-eth0"
os.system(f"ip link set {iface} up")

def cpu_sampler():
    while True:
        cpu = psutil.cpu_percent(interval=1)
        stats['cpu'] = cpu
        if cpu > stats['peak_cpu']:
            stats['peak_cpu'] = cpu

def process_pkt(pkt):
    if pkt.haslayer(IPv6) and pkt.haslayer(TCP):
        src = pkt[IPv6].src
        is_syn = bool(pkt[TCP].flags & 0x02)
        if is_syn:
            stats['syn'] += 1
        else:
            stats['other'] += 1
        if src in ATTACKER_IPS:
            stats['attack_reached'] += 1
        elif src in LEGIT_IPS:
            stats['legit_reached'] += 1

    sys.stdout.write(
        f"\r[h2] SYN:{stats['syn']}  Other:{stats['other']}  "
        f"|  CPU:{stats['cpu']:.1f}%  Peak:{stats['peak_cpu']:.1f}%   "
    )
    sys.stdout.flush()

def print_results():
    ar = stats['attack_reached']
    lr = stats['legit_reached']

    FN = ar
    TN = lr
    TP = TOTAL_ATTACK_SENT - FN
    FP = TOTAL_LEGIT_SENT - TN
    FP = max(FP, 0)
    TN = min(TN, TOTAL_LEGIT_SENT)

    total = TP + TN + FP + FN
    accuracy  = (TP + TN) / total             if total > 0         else 0
    precision = TP / (TP + FP)                if (TP + FP) > 0     else 1.0
    recall    = TP / (TP + FN)                if (TP + FN) > 0     else 1.0
    f1        = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0

    print("\n")
    print("=" * 50)
    print("  RESULTS")
    print("=" * 50)
    print(f"  Attack packets sent       : {TOTAL_ATTACK_SENT}")
    print(f"  Legit packets sent        : {TOTAL_LEGIT_SENT}")
    print(f"  Attack reached h2   (FN)  : {FN}")
    print(f"  Legit reached h2    (TN)  : {TN}")
    print(f"  Attack blocked      (TP)  : {TP}")
    print(f"  Legit blocked       (FP)  : {FP}")
    print("-" * 50)
    print(f"  Accuracy                  : {accuracy:.2%}")
    print(f"  Precision                 : {precision:.2%}")
    print(f"  Recall                    : {recall:.2%}")
    print(f"  F1 Score                  : {f1:.2%}")
    print(f"  Peak CPU                  : {stats['peak_cpu']:.1f}%")
    print("=" * 50)
    sys.exit(0)

def handle_signal(sig, frame):
    print_results()

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

threading.Thread(target=cpu_sampler, daemon=True).start()

print(f"Monitor started on {iface}. Watching packets + CPU. Ctrl+C to stop.")
sniff(iface=iface, prn=process_pkt, store=0)