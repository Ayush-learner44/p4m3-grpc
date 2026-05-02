# P4M3 — SYN Flood DDoS Detection (Pure gRPC)

P4-based SYN flood detection system running on a virtual leaf-spine network using BMv2 (`simple_switch_grpc`) and P4Runtime gRPC. The controller receives packet features directly over the bidirectional gRPC stream — no CPU port sniffing, no virtual interface binding.

---

## How It Works

Three-layer detection pipeline:

### Layer 1 — dangerous_table (Algorithm 1)
Every packet hits this first. If the source MAC is in the blocklist (installed by the controller after ML detection), the packet is dropped immediately in the data plane. Zero latency.

### Layer 2 — Count-Min Sketch (Algorithm 2)
For every IPv6 TCP SYN packet not in the blocklist:
- Two hash functions (CRC16 + CRC32) update a 1024-column CMS register
- If CMS count > 100 (threshold) → drop in data plane immediately
- If CMS count ≤ 100 → send features to controller via P4Runtime digest, forward packet normally

### Layer 3 — ML Ensemble (Algorithm 3)
Controller receives digest messages pushed over the gRPC stream from the switch. After every 27 packets from the same MAC, it classifies the flow using a 5-model ensemble (KNN, Random Forest, Decision Tree, XGBoost, SVM). Majority vote decides:
- **Attack** → push drop rule to `dangerous_table` on all switches, block permanently
- **Benign** → allow, do nothing

---

## Why Pure gRPC

Previous versions used `clone_preserving_field_list` to clone SYN packets to a CPU port, then sniffed a virtual interface (`leaf1-cpu-eth1`) with a raw socket. This version replaces that entire mechanism with `digest<cpu_digest_t>(1, {...})` in the P4 pipeline. The switch pushes a 16-byte struct over the already-open P4Runtime gRPC stream the instant a SYN fires — no extra interfaces, no raw sockets, no polling.

---

## Topology

```
h1a (attacker) ─┐
h1b (attacker) ─┤─ leaf1 ─┐
h1c (attacker) ─┘          │
                         spine1 ─── leaf2 ─── h2 (victim)
h3a (benign)  ─┐          │
h3b (benign)  ─┤─ leaf3 ─┘
h3c (benign)  ─┘
```

- **leaf1, leaf3**: digest-enabled, features pushed to controller via gRPC
- **leaf2, spine1**: L2 forwarding only
- **h1a, h1b, h1c**: send attack traffic (SYN flood, inter=0.01s → ~100 pps)
- **h3a, h3b, h3c**: send benign traffic (inter=0.5s → ~2 pps)
- **h2**: victim, receives all traffic, run monitor.py here

---

## Project Structure

```
p4m3_pure_grpc/
├── network.py              # Mininet topology + P4RuntimeSwitch config
├── run_all.py              # Launch all host scripts from Mininet CLI
├── monitor.py              # Packet + CPU monitor running on h2
├── monitor_controller.py   # Controller-side stats monitor
├── server.py               # Optional stats server
├── attack1/2/3.py          # Scapy SYN flood scripts (h1a, h1b, h1c)
├── good1/2/3.py            # Scapy benign SYN scripts (h3a, h3b, h3c)
├── p4src/
│   └── ddos_detector.p4    # P4 program (digest replaces clone)
├── controller/
│   └── controller.py       # P4Runtime gRPC controller + ML ensemble
└── ml/
    └── models/             # Pre-trained .pkl files (copy manually)
        ├── knn_model.pkl
        ├── rf_model.pkl
        ├── dt_model.pkl
        ├── xgb_model.pkl
        ├── svm_model.pkl
        └── scaler.pkl
```

---

## Prerequisites

- Ubuntu (WSL or native)
- [p4-utils](https://github.com/nsg-ethz/p4-utils) installed at `/home/ayush/p4-tools/p4-utils`
- Mininet
- `simple_switch_grpc` (BMv2 with P4Runtime support)
- Python packages: `scapy`, `numpy`, `psutil`, `sklearn`, `xgboost`

---

## How to Run

### Step 1 — Start the network
Open a terminal in WSL:
```bash
cd /home/ayush/p4m3_pure_grpc
sudo python3 network.py
```
Wait until the Mininet CLI appears (`mininet>`). The P4 compiler runs automatically and generates `p4src/ddos_detector_p4rt.txt` and `p4src/ddos_detector.json`.

### Step 3 — Start the controller
Open a second terminal:
```bash
cd /home/ayush/p4m3_pure_grpc
sudo python3 controller/controller.py
```
The controller will:
- Connect to all 4 switches via gRPC
- Install L2 forwarding rules
- Enable digest on leaf1 and leaf3
- Start blocking on the gRPC stream (no CPU port sniffing)

### Step 4 — Run traffic
Back in the Mininet CLI:
```
mininet> py exec(open('/home/ayush/p4m3_pure_grpc/run_all.py').read())
```
This launches attack and benign scripts on all hosts simultaneously.

### Step 5 — Monitor h2 (optional)
```
mininet> h2 python3 /home/ayush/p4m3_pure_grpc/monitor.py &
```
Shows live SYN count and CPU usage at the victim host.

---

## Expected Output

**Controller terminal:**
```
ATTACK DETECTED: 2a:ac:90:97:e9:78
  PPS=500000.0  Vote=5/5  -> BLOCKING on all switches
BENIGN: 36:67:4e:e1:ec:8a (10000.0 pps) -> allowed
STATS | Received:81  Attacks:3  Benign:3  Blocked:3
```

**After ~27 packets per attacker MAC**, the controller classifies and blocks. Subsequent packets from that MAC are dropped at Layer 1 in the data plane — the controller is not involved again.

---

## Key Parameters

| Parameter | Value | Location |
|-----------|-------|----------|
| Window size (packets before classify) | 27 | `controller.py` `WINDOW_SIZE` |
| CMS threshold (drop in data plane) | 100 | `ddos_detector.p4` `THRESHOLD` |
| CMS columns | 1024 | `ddos_detector.p4` `CMS_COLS` |
| PPS scale multiplier | 5000x | `controller.py` `EnsembleClassifier.predict` |
| Digest receiver ID | 1 | `ddos_detector.p4` + `controller.py` |
| gRPC ports | 9559–9562 | `network.py` |

---

## Difference from p4m3_grpc

| | p4m3_grpc | p4m3_pure_grpc |
|--|-----------|----------------|
| Switch→Controller delivery | `clone_preserving_field_list` → CPU port → raw socket sniff | `digest<cpu_digest_t>` → gRPC stream |
| CPU virtual interfaces | Yes (`leaf1-cpu-eth1`, `leaf3-cpu-eth1`) | None |
| Controller imports | `socket`, `struct` | Neither |
| Egress logic | Adds `cpu_in_header_t` to clone | Empty |
| Data sent | Full cloned packet (100+ bytes) | 16-byte struct |
