# Proxy for debugging (idk how to debug as root)

from time import sleep
import socket

down = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

up.bind(("127.0.0.1", 9500))
down.setblocking(0)
up.setblocking(0)

daddr, uaddr = ((), ("127.0.0.1", 5000))

while True:
\ttry:
\t\tbuf, daddr = down.recvfrom(65535)
\t\tup.sendto(buf, uaddr)
\texcept BlockingIOError:
\t\tpass
\ttry:
\t\tbuf, uaddr = up.recvfrom(65535)
\t\tdown.sendto(buf, daddr)
\texcept BlockingIOError:
\t\tpass
\tsleep(0.001)
