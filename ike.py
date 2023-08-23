# Very bad IKEv2 server implementation

from random import randint
from socket import socket, AF_INET6, SOCK_DGRAM
from struct import pack, unpack, pack_into, unpack_from
from threading import Thread
from time import sleep

import os

from classes import *

# Exchange types
IKE_SA_INIT = 34

# Payload types
IKEV2_PAYLOAD_SA = 33
IKEV2_PAYLOAD_KE = 34
IKEV2_PAYLOAD_NONCE = 40
IKEV2_PAYLOAD_NOTIFY = 41

# Notification types
IKEV2_NOTIFY_INVALID_KE_PAYLOAD = 17

# DH params
DH_G = 2
DH_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff

s = socket(AF_INET6, SOCK_DGRAM)
s.bind(("::", 5000 if os.getuid() else 500))

thing: dict[bytes, tuple[list[bytes]]] = {}

def recv(id):
	while len(thing[id][0]) == 0:
		sleep(0.001)
	return thing[id][0].pop(0)

def packetize(buf):
	exchange = buf[18]
	mid, = unpack_from("!L", buf, 20)
	packets = []
	type = buf[16]
	# TODO: Parse and verify header here
	buf = buf[28:]
	while len(buf):
		l, = unpack_from("!H", buf, 2)
		packets.append((type, buf[4:l]))
		type = buf[0]
		buf = buf[l:]
	return exchange, mid, packets

def notify(id, exchange, mid, type, msg):
	d = b'\x00\x00' + pack("!H", type) + msg # Notify payload + notification data
	p = Payload(IKEV2_PAYLOAD_NOTIFY, [Raw(d)]) # Notify payload + header
	msg = Message(id, exchange, mid, True, False, [p]).build() # Message header + notify payload
	s.sendto(msg, thing[id][1])

def handle(id):
	redo = True
	while redo:
		redo = False
		exchange, mid, messages = packetize(recv(id))
		if exchange != IKE_SA_INIT:
			# reject(id, "you fucker")
			print("Client sent data before init")
			return
		k = None
		for type, buf in messages:
			if type == IKEV2_PAYLOAD_SA:
				pass
			elif type == IKEV2_PAYLOAD_KE:
				grp, = unpack_from("!H", buf, 0)
				if grp != 14:
					notify(id, IKE_SA_INIT, mid, IKEV2_NOTIFY_INVALID_KE_PAYLOAD, b'\x00\x0e') # We accept group 14
					redo = True
					break
		if redo: continue

if __name__ == "__main__":
	while True:
		buf, a = s.recvfrom(65535)
		# buf = b'\x3a\x2e\xf8\xeb\xbf\x48\x72\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x02\x8c\x22\x00\x00\xf4\x02\x00\x00\x88\x01\x01\x00\x0f\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x01\x00\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80\x03\x00\x00\x08\x03\x00\x00\x0e\x03\x00\x00\x08\x03\x00\x00\x0d\x03\x00\x00\x08\x03\x00\x00\x0c\x03\x00\x00\x08\x03\x00\x00\x02\x03\x00\x00\x08\x02\x00\x00\x07\x03\x00\x00\x08\x02\x00\x00\x06\x03\x00\x00\x08\x02\x00\x00\x05\x03\x00\x00\x08\x02\x00\x00\x02\x03\x00\x00\x08\x04\x00\x00\x18\x03\x00\x00\x08\x04\x00\x00\x14\x03\x00\x00\x08\x04\x00\x00\x13\x03\x00\x00\x08\x04\x00\x00\x0e\x00\x00\x00\x08\x04\x00\x00\x05\x00\x00\x00\x68\x02\x01\x00\x0b\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x01\x00\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x00\x80\x03\x00\x00\x08\x02\x00\x00\x07\x03\x00\x00\x08\x02\x00\x00\x06\x03\x00\x00\x08\x02\x00\x00\x05\x03\x00\x00\x08\x02\x00\x00\x02\x03\x00\x00\x08\x04\x00\x00\x18\x03\x00\x00\x08\x04\x00\x00\x14\x03\x00\x00\x08\x04\x00\x00\x13\x03\x00\x00\x08\x04\x00\x00\x0e\x00\x00\x00\x08\x04\x00\x00\x05\x28\x00\x01\x08\x00\x18\x00\x00\x69\x6c\x2d\x12\x82\x28\xec\x52\xcb\x21\xbd\x50\x56\x65\x5d\xd9\x49\x85\x4e\x6b\x6e\xe8\x2f\x87\x7a\x2a\x9f\x3d\xa6\xf9\x95\x31\x79\x58\x58\xea\xc4\x3c\x11\x2b\x3b\x79\x9e\x64\x2a\x90\xb3\x05\xea\x1a\x79\x04\x17\x5e\xa9\x95\xa6\x2d\xae\x1e\xa8\x0c\x6f\x18\x3d\x1c\x42\x2a\x7a\xed\x92\x2b\x98\x85\x9b\x18\x6c\xdc\x8f\xd3\x73\x44\x50\xdb\xe6\x8f\x0f\x2a\xaa\xf4\xb6\x0a\xa3\x49\xfc\x7b\x16\x27\x32\x92\x02\x60\xb3\xb1\x6c\x64\x56\xf1\xd8\x47\x22\xba\x25\x36\xd7\xa2\x95\x8f\x55\x89\x3e\xf5\xd9\xdc\x36\xa2\x04\xea\xbf\xca\x89\x26\x0e\x6f\x09\xea\x3d\xdc\x28\x91\x26\x35\x4a\x5a\xde\x40\x28\x04\x1b\x2e\x34\xb9\x07\x9b\xe2\xdd\xad\xa8\x17\x3e\xa1\xca\xc8\x0a\x5d\xa5\x47\xc1\xef\xb9\xf8\x65\x5d\x0c\x9a\x4c\x6b\xf3\x1f\xc1\x3d\xeb\xbc\x2f\x4c\x59\xf8\x51\x09\x3c\xaf\x9c\xfd\xf3\x0a\x8e\x5e\x3e\x86\xed\xba\x65\xcd\xd5\x4e\x6c\x75\xb9\xdc\xc1\x7a\xf1\x28\xa5\x99\xbd\xb9\x77\x27\x12\x4e\x69\x6f\x2a\x23\x84\x13\xa7\x5f\x1d\x8c\xf7\x40\x40\xf5\x8b\xe5\xa9\xec\x40\x59\xd0\x20\xc0\x2a\x5a\x8e\xfa\x31\x5c\xe5\x6c\x10\x00\xd8\x28\x29\x00\x00\x24\x80\x08\x3f\x07\x70\xd0\x4c\x0a\x9c\x1f\x38\x9d\xe0\x48\x2d\x59\x39\x89\x51\xc1\x4d\x85\xfe\x45\xd7\x3b\x6e\x35\xf9\xe6\x0f\xe1\x29\x00\x00\x1c\x00\x00\x40\x04\xc0\xda\x52\x87\xc2\xef\x53\x63\x0d\xfc\x70\xf2\x4a\x39\x40\x69\x99\xea\x3d\x37\x29\x00\x00\x1c\x00\x00\x40\x05\x8c\x1f\xda\x49\x5e\x45\x9a\xf0\x44\x70\x9a\x60\x3f\x56\x81\x13\xe2\xe6\xb1\xa6\x29\x00\x00\x10\x00\x00\x40\x2f\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00\x08\x00\x00\x40\x16'
		# a = ("::1", 21378)
		try:
			cid, sid = unpack_from("!QQ", buf, 0)
			id = buf[:16]
			if sid == 0:
				# New connection
				sid = randint(1, 0xffffffffffffffff)
				id = pack("!QQ", cid, sid)
				thing[id] = ([buf], a)
				# handle(id)
				Thread(target=handle, args=(id,), daemon=True).start()
				break
			else:
				# Append to existing queue
				thing[id][0].append(buf)
		except: pass