import socket, threading, sys
def handle(c):
    try:
        c.settimeout(30)
        c.recv(4096)  # gopher selector from squid
        line = b'A' * 4094 + b'\n'   # llen = 4095 = TEMP_BUF_SIZE-1
        c.sendall(line)
        import time; time.sleep(25)
    except Exception as e:
        print('srv err:', e, file=sys.stderr)
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 17070)); s.listen(4)
print('gopher fake server on 17070', flush=True)
while True:
    c,_ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
