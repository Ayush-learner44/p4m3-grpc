from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()
net.setLogLevel('info')

# Switches — P4RuntimeSwitch enables gRPC/P4Runtime control plane
net.addP4RuntimeSwitch('leaf1')
net.addP4RuntimeSwitch('leaf2')
net.addP4RuntimeSwitch('leaf3')
net.addP4RuntimeSwitch('spine1')
net.setP4SourceAll('p4src/ddos_detector.p4')
net.setCompiler(p4rt=True)   # generates ddos_detector_p4rt.txt alongside ddos_detector.json

# Hosts
net.addHost('h1a')
net.addHost('h1b')
net.addHost('h1c')
net.addHost('h2')
net.addHost('h3a')
net.addHost('h3b')
net.addHost('h3c')

# Links with explicit port numbers
# leaf1: h1a=1, h1b=2, h1c=3, spine1=4
net.addLink('leaf1', 'h1a',    port1=1, port2=0)
net.addLink('leaf1', 'h1b',    port1=2, port2=0)
net.addLink('leaf1', 'h1c',    port1=3, port2=0)
net.addLink('leaf1', 'spine1', port1=4, port2=1)

# leaf2: h2=1, spine1=2
net.addLink('leaf2', 'h2',     port1=1, port2=0)
net.addLink('leaf2', 'spine1', port1=2, port2=2)

# leaf3: h3a=1, h3b=2, h3c=3, spine1=4
net.addLink('leaf3', 'h3a',    port1=1, port2=0)
net.addLink('leaf3', 'h3b',    port1=2, port2=0)
net.addLink('leaf3', 'h3c',    port1=3, port2=0)
net.addLink('leaf3', 'spine1', port1=4, port2=3)

# No CPU ports — digest() sends features via gRPC stream directly,
# no virtual interface (leaf*-cpu-eth*) needed.

# MACs — must match the hardcoded values in attack1/2/3 and good1/2/3 scripts
net.setIntfMac('h1a', 'leaf1', '2a:ac:90:97:e9:78')
net.setIntfMac('h1b', 'leaf1', '96:29:cc:a3:3d:7f')
net.setIntfMac('h1c', 'leaf1', '7e:8d:d4:8f:0e:67')
net.setIntfMac('h2',  'leaf2', 'f2:44:a6:63:0a:48')
net.setIntfMac('h3a', 'leaf3', '36:67:4e:e1:ec:8a')
net.setIntfMac('h3b', 'leaf3', 'b2:7f:69:b5:af:21')
net.setIntfMac('h3c', 'leaf3', '92:5d:3d:47:c2:94')

# IPv6 addresses — manual assignment (auto-strategies are IPv4 only)
net.setIntfIp('h1a', 'leaf1', '2001:1:1::1/64')
net.setIntfIp('h1b', 'leaf1', '2001:1:1::2/64')
net.setIntfIp('h1c', 'leaf1', '2001:1:1::3/64')
net.setIntfIp('h2',  'leaf2', '2001:2:1::1/64')
net.setIntfIp('h3a', 'leaf3', '2001:3:1::1/64')
net.setIntfIp('h3b', 'leaf3', '2001:3:1::2/64')
net.setIntfIp('h3c', 'leaf3', '2001:3:1::3/64')

# No ARP needed — Scapy scripts use sendp() with hardcoded MACs (L2 injection)
net.disableArpTables()
net.disableGwArp()

# Thrift ports (P4RuntimeSwitch still exposes Thrift — kept for compatibility)
net.setThriftPort('leaf1',  9090)
net.setThriftPort('leaf2',  9091)
net.setThriftPort('leaf3',  9092)
net.setThriftPort('spine1', 9093)

# gRPC ports for P4Runtime controller
net.setGrpcPort('leaf1',  9559)
net.setGrpcPort('leaf2',  9560)
net.setGrpcPort('leaf3',  9561)
net.setGrpcPort('spine1', 9562)

net.enableLogAll()
# net.enablePcapDumpAll()
net.enableCli()
net.startNetwork()
