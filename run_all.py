"""
Run from mininet CLI:
    mininet> py exec(open('/home/ayush/p4m3-grpc/run_all.py').read())
"""
import time

BASE = '/home/ayush/p4m3-grpc'

hosts_scripts = [
    ('h1a', 'attack1.py'),
    ('h1b', 'attack2.py'),
    ('h1c', 'attack3.py'),
    ('h3a', 'good1.py'),
    ('h3b', 'good2.py'),
    ('h3c', 'good3.py'),
]

for host, script in hosts_scripts:
    net.get(host).cmd(f'cd {BASE} && python3 {script} > /tmp/p4m3_{host}.log 2>&1 &')
    print(f'[run_all] {host} -> {script}')

print('[run_all] All launched simultaneously.')
print('[run_all] Logs: mininet> py net.get("h1a").cmd("cat /tmp/p4m3_h1a.log")')