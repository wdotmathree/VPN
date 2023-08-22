# Trying to parse IPSec when it comes to that

from socket import socket, AF_PACKET, SOCK_RAW, htons
from struct import unpack, unpack_from

s = socket(AF_PACKET, SOCK_RAW, 0x0300)
s.bind(("lo", 0))

while True:
	buf = s.recv(65636)
	ethertype = unpack_from("!h", buf, 12)[0]
	len = 0
	start = 0
	proto = 0
	if ethertype == 0x0800:
		len = unpack_from("!h", buf, 16)[0]
		start = 34
		proto = buf[23]
	elif ethertype == 0x86dd:
		len = unpack_from("!h", buf, 18)[0]
		start = 54
		proto = buf[20]
	else: continue
	