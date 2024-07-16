from queue import Queue, Empty
from time import sleep, time
import random
import socket

espSocket: socket.socket = None
tcpSocket: socket.socket = None
ourIP = None
thing: dict[bytes, tuple[Queue[bytes]]] = None

tcpMap: dict[bytes, list[int, int]] = {} # id:srcPort -> [localPort, lastPacketTime]
tcpRevMap: dict[int, tuple[bytes, int]] = {} # localPort -> (id, srcPort)
udpMap: dict[bytes, list[int, int]] = {} # id:srcPort -> [localPort, lastPacketTime]
udpRevMap: dict[int, tuple[bytes, int]] = {} # localPort -> (id, srcPort)


def endAroundSum16(data):
	res = 0
	for i in range(0, len(data), 2):
		if i + 1 >= len(data):
			res += data[i] << 8
		else:
			res += (data[i] << 8) | data[i + 1]
	while res > 0xffff:
		res = (res & 0xffff) + (res >> 16)
	return res


def endAroundAdd16(*args):
	res = 0
	for arg in args:
		res += arg
	while res > 0xffff:
		res = (res & 0xffff) + (res >> 16)
	return res


def handleTCP(id, dec, address, checksumDiff):
	key = id + dec[0:2]
	if key not in tcpMap:
		# Register a port for this connection
		localPort = random.randint(40000, 40099)
		while localPort in tcpRevMap:
			localPort = random.randint(40000, 40099)
		tcpRevMap[localPort] = (id, dec[0] << 8 | dec[1])
		tcpMap[key] = [localPort, int(time())]
	localPort = tcpMap[key][0]
	chksum = endAroundAdd16((dec[16] << 8 | dec[17]) ^ 0xffff, checksumDiff, localPort, -(dec[0] << 8 | dec[1]), 0xffff)
	dec = localPort.to_bytes(2, "big") + dec[2:16] + (chksum ^ 0xffff).to_bytes(2, "big") + dec[18:]
	print("new", dec)
	tcpSocket.sendto(dec, (address, 6))


def handleUDP(id, dec):
	pass


def handleIPv4(id, dec):
	print("old", dec)
	if dec[9] == 6:
		# Compute the difference between the new and old Source IPs
		checksumDiff = endAroundAdd16(
			(ourIP[0] + ourIP[2]) << 8,
			(ourIP[1] + ourIP[3]),
			-(dec[12] << 8 | dec[13]),
			-(dec[14] << 8 | dec[15]),
			0xffff + 0xffff,
		)
		handleTCP(id, dec[20:], socket.inet_ntop(socket.AF_INET, dec[16:20]), checksumDiff)
	elif dec[9] == 17:
		handleUDP(id, dec[20:])
	else:
		print("(handleIPv4) Unknown protocol:", dec[9], ". Dropping packet.")


def handleIncomingPacket(msg):
	id, nextHead, dec = msg
	if nextHead == 4:
		handleIPv4(id, dec)
	else:
		print("(handleIncomingPacket) Unknown next header:", nextHead, ". Dropping packet.")


def handleOutgoingPacket(buf):
	pass
	# proto = buf[9]
	# if proto == 6:
	# 	port = (buf[22] << 8) | buf[23]
	# 	if port in tcpRevMap:
	# 		id = tcpRevMap[port]
	# 		# Forward packet
	# 		# s.sendto(buf, thing[id]['a'])


def main(thing_in, forwardq):
	global espSocket, tcpSocket, clearRecvSocket, thing, ourIP
	thing = thing_in

	tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tmp.settimeout(0)
	tmp.connect(("1.1.1.1", 1))
	ourIP = socket.inet_pton(socket.AF_INET, tmp.getsockname()[0])
	tmp.close()
	del tmp

	espSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
	tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	garbage = []
	# Reserve ports
	for i in range(40000, 40100):
		try:
			tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			tmp.bind(("0.0.0.0", i))
			tmp.listen(2147483647)
			garbage.append(tmp)
		except socket.error as e:
			if e.errno == socket.errno.EADDRINUSE:
				tcpRevMap[i] = [b'', -1]
			else:
				print(e)
		try:
			tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			tmp.bind(("0.0.0.0", i))
			garbage.append(tmp)
		except socket.error as e:
			if e.errno == socket.errno.EADDRINUSE:
				udpRevMap[i] = [b'', -1]
			else:
				print(e)

	while True:
		processed = False
		try:
			msg = forwardq.get_nowait()
		except Empty:
			msg = None
		while msg is not None:
			processed = True
			handleIncomingPacket(msg)
			try:
				msg = forwardq.get_nowait()
			except Empty:
				break
		# for id in list(tcpMap.keys()):
		# 	try:
		# 		handleOutgoingPacket(tcpMap[id][0].recv(65535))
		# 		processed = True
		# 		tcpMap[id][1] = int(time())
		# 	except BlockingIOError:
		# 		if int(time()) - tcpMap[id][1] > 60:
		# 			tcpMap[id][0].close()
		# 			# killTCP(id)
		# 			del tcpRevMap[tcpMap[id][0].getsockname()[1]]
		# 			del tcpMap[id]
		if not processed:
			sleep(0.001)
