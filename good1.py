import time, logging
from scapy.all import Ether, IPv6, TCP, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SRC_MAC = "36:67:4e:e1:ec:8a"
DST_MAC = "f2:44:a6:63:0a:48"
VICTIM_IP = "2001:2:1::1"
IFACE = "h3a-eth0"
NUM_PACKETS = 60

print(f"Sending {NUM_PACKETS} Benign SYNs from h3a ({SRC_MAC}) out of {IFACE}...")
for i in range(NUM_PACKETS):
    pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IPv6(src="2001:3:1::1",dst=VICTIM_IP)/TCP(dport=80, sport=51000, flags="S")
    sendp(pkt, iface=IFACE, verbose=0)
    time.sleep(0.5)
print("h3a benign traffic complete.")
