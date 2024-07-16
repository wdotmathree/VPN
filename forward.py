from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from netfilterqueue import NetfilterQueue
from queue import Queue, Empty
from time import sleep, time
import random
import socket
import struct
import sys


espSocket: socket.socket = None
tcpSendSocket: socket.socket = None
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


def clamp16(val):
	while val < 0:
		val += 0xffff
	while val > 0xffff:
		val = (val & 0xffff) + (val >> 16)
	return val


def handleIncomingTCP(id, dec, address, checksumDiff):
	key = id + dec[0:2]
	if key not in tcpMap:
		# Register a port for this connection
		localPort = random.randint(40000, 40099)
		while localPort in tcpRevMap:
			localPort = random.randint(40000, 40099)
		tcpRevMap[localPort] = (id, dec[0] << 8 | dec[1])
		tcpMap[key] = [localPort, int(time())]
	else:
		tcpMap[key][1] = int(time())
	localPort = tcpMap[key][0]
	chksum = clamp16(((dec[16] << 8 | dec[17]) ^ 0xffff) + checksumDiff + localPort - (dec[0] << 8 | dec[1]))
	dec = localPort.to_bytes(2, "big") + dec[2:16] + (chksum ^ 0xffff).to_bytes(2, "big") + dec[18:]
	tcpSendSocket.sendto(dec, (address, 6))


def handleIncomingUDP(id, dec):
	print("(handleIncomingUDP) Not implemented yet, dropping packet.", file=sys.stderr)
	pass


def handleIncomingIPv4(id, dec):
	if dec[9] == 6:
		# Compute the difference between the new and old Source IPs
		checksumDiff = clamp16(((ourIP[0] + ourIP[2]) << 8) + (ourIP[1] + ourIP[3]) - (dec[12] << 8 | dec[13]) - (dec[14] << 8 | dec[15]))
		handleIncomingTCP(id, dec[20:], socket.inet_ntop(socket.AF_INET, dec[16:20]), checksumDiff)
	elif dec[9] == 17:
		handleIncomingUDP(id, dec[20:])
	else:
		print("(handleIPv4) Unknown protocol:", dec[9], ". Dropping packet.", file=sys.stderr)


def handleIncomingPacket(msg):
	print("incoming")
	id, nextHead, dec = msg
	if nextHead == 4:
		handleIncomingIPv4(id, dec)
	else:
		print("(handleIncomingPacket) Unknown next header:", nextHead, ". Dropping packet.", file=sys.stderr)


def espSend(id, nextHead, buf):
	# Pick an IV
	iv = random.randbytes(16)
	# Pad to 16n-2
	padLen = 16 - (len(buf) + 2) % 16
	buf += bytes([i + 1 for i in range(padLen)]) + bytes([padLen, nextHead])
	# Encrypt
	enc = AES.new(thing[id]['ek'], AES.MODE_CBC, iv).encrypt(buf)
	# Construct message
	msg = struct.pack("!4sL", id, thing[id]['rseq'] + 1) + iv + enc
	thing[id]['rseq'] += 1
	# Compute ICV
	msg += HMAC.new(thing[id]['ak'], msg, SHA256).digest()[:16]
	# Send
	espSocket.sendto(msg, thing[id]['a'])


def handleOutgoingTCP(buf, checksumDiff):
	localPort = buf[22] << 8 | buf[23]
	id, dstPort = tcpRevMap[localPort]
	chksum = clamp16(((buf[36] << 8 | buf[37]) ^ 0xffff) + checksumDiff + (dstPort - localPort))
	buf = buf[:22] + dstPort.to_bytes(2, "big") + buf[24:36] + (chksum ^ 0xffff).to_bytes(2, "big") + buf[38:]
	espSend(id, 4, buf)


def handleOutgoingPacket(buf):
	proto = buf[9]
	if proto == 6:
		id = tcpRevMap.get(buf[22] << 8 | buf[23])[0]
	else:
		print("(handleOutgoingPacket) Unknown protocol:", proto, ". Dropping packet.", file=sys.stderr)

	if id is None:
		# This packet is not for us
		return
	clientIp = socket.inet_pton(socket.AF_INET, thing[id]['a'][0])
	checksumDiff = clamp16(((clientIp[0] + clientIp[2]) << 8) + (clientIp[1] + clientIp[3]) - (buf[16] << 8 | buf[17]) - (buf[18] << 8 | buf[19]))
	buf = buf[:10] + (clamp16(((buf[10] << 8 | buf[11]) ^ 0xffff) + checksumDiff) ^ 0xffff).to_bytes(2, "big") + buf[12:16] + clientIp + buf[20:]
	if proto == 6:
		handleOutgoingTCP(buf, checksumDiff)


def garbageCollect():
	now = int(time())
	for key in list(tcpMap.keys()):
		if now - tcpMap[key][1] > 60:
			# kill(key)
			del tcpRevMap[tcpMap[key][0]]
			del tcpMap[key]
	for key in list(udpMap.keys()):
		if now - udpMap[key][1] > 60:
			del udpRevMap[udpMap[key][0]]
			del udpMap[key]


def nfqCallback(packet):
	handleOutgoingPacket(packet.get_payload())
	packet.drop()


def main(thing_in, forwardq):
	global espSocket, tcpSendSocket, thing, ourIP
	thing = thing_in

	tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tmp.settimeout(0)
	tmp.connect(("1.1.1.1", 1))
	ourIP = socket.inet_pton(socket.AF_INET, tmp.getsockname()[0])
	tmp.close()
	del tmp

	espSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
	tcpSendSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	nfq = NetfilterQueue()
	nfq.bind(12, nfqCallback)

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
				print("(reserveTCP)", e, file=sys.stderr)
		try:
			tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			tmp.bind(("0.0.0.0", i))
			garbage.append(tmp)
		except socket.error as e:
			if e.errno == socket.errno.EADDRINUSE:
				udpRevMap[i] = [b'', -1]
			else:
				print("(reserveTCP)", e, file=sys.stderr)

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

		nfq.run(False)

		garbageCollect()

		if not processed:
			sleep(0.001)
