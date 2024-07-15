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
