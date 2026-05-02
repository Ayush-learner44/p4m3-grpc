import socket, threading

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 80))
s.listen(1000)
print('[server] Listening on [::]:80')

while True:
    conn, _ = s.accept()
    threading.Thread(target=conn.close, daemon=True).start()
