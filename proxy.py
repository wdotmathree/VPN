# Proxy for debugging (idk how to debug as root)

from socket import *
from time import sleep

down = socket(AF_INET, SOCK_DGRAM)
up = socket(AF_INET, SOCK_DGRAM)

down.bind(("0.0.0.0", 500))
up.bind(("127.0.0.1", 9500))
down.setblocking(0)
up.setblocking(0)

daddr, uaddr = ((),("127.0.0.1", 4500))

while True:
    try:
        buf, daddr = down.recvfrom(65535)
        up.sendto(buf, uaddr)
    except BlockingIOError:
        pass
    try:
        buf, uaddr = up.recvfrom(65535)
        down.sendto(buf, daddr)
    except BlockingIOError:
        pass
    sleep(0.001)
