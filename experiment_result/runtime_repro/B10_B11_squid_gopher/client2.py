import socket, sys
s = socket.create_connection(('127.0.0.1', 13128), timeout=20)
s.sendall(b"GET gopher://127.0.0.1:17070/1 HTTP/1.1\r\nHost: 127.0.0.1:17070\r\n\r\n")
s.settimeout(12)
total = b''
try:
    while True:
        d = s.recv(65536)
        if not d: break
        total += d
except Exception as e:
    print('timeout/err:', e)
hdr, _, body = total.partition(b'\r\n\r\n')
print('body len:', len(body))
print('body head:', body[:200])
print('A-count:', body.count(b'A'))
