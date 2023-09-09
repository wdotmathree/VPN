# Very bad IKEv2 server implementation

from random import randint
from socket import socket, AF_INET6, SOCK_DGRAM
from struct import pack, unpack, pack_into, unpack_from
from threading import Thread
from time import sleep
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC

import os

from classes import *
from consts import *

s = socket(AF_INET6, SOCK_DGRAM)
s.bind(("::", 4500 if os.getuid() else 500))


def recv(id):
	while len(thing[id][0]) == 0:
		sleep(0.001)
	return thing[id][0].pop(0)

def notify(id, exchange, mid, type, msg):
	d = b'\x00\x00' + pack("!H", type) + msg # Notify payload + notification data
	p = Payload(IKEV2_PAYLOAD_NOTIFY, [Raw(d)]) # Notify payload + header
	msg = Message(id, exchange, mid, True, False, [p]).build() # Message header + notify payload
	s.sendto(msg, thing[id][1])

def parse_proposal(proposal: Proposal):
	num = 0
	for t in proposal.children:
		if type(t) == Raw: continue
		if t.transtype == 1: # Encryption
			if t.id == 12: # AES-CBC
				if t.children[0].data == b'\x01\x00':
					num += 1
		elif t.transtype == 3: # Integrity
			if t.id == 12: # HMAC-SHA256-128
				num += 1
		elif t.transtype == 2: # PRF
			if t.id == 5: # PRF-HMAC-SHA256
				num += 1
		elif t.transtype == 4: # Diffie-Hellman
			if t.id == 14: # Group 14
				num += 1
	return num == 4


def sa_init(id, m: Message):
	reply = Message(id, IKE_SA_INIT, m.mid, True, False, [])
	gi = None
	ni = None
	r = None
	gr = None
	nr = None
	with open("/dev/urandom", "rb") as f:
		r = f.read(256)
		nr = f.read(32)
	r = int.from_bytes(r, 'big')
	gr = pow(2, r, DH_P).to_bytes(256, 'big').rjust(256, b'\x00')
	for p in m.children:
		if p.type == IKEV2_PAYLOAD_SA:
			# Look for supported stuff
			success = 0
			for proposal in p.children:
				if parse_proposal(proposal):
					success = proposal.num
					break
			if not success:
				raise IKEException((IKEV2_NOTIFY_NO_PROPOSAL, b''), m.exchange, m.mid)
			# Build reply
			p = SAPayload([Proposal(success, 1, b'', [Transform(1, 12, [Attribute(14, b'\x01\x00')]), Transform(3, 12, []), Transform(2, 5, []), Transform(4, 14, [])])])
			reply.addChild(p)
		elif p.type == IKEV2_PAYLOAD_KE:
			if p.dh_group != 14:
				raise IKEException((IKEV2_NOTIFY_INVALID_KE_PAYLOAD, b'\x00\x0e'), m.exchange, m.mid) # We only accept group 14
			gi = p.children[0].data
			# Build reply
			p = KEPayload(14, gr)
			del gr
			reply.addChild(p)
		elif p.type == IKEV2_PAYLOAD_NONCE:
			ni = p.children[0].data
			# Build reply
			p = NoncePayload(nr)
			reply.addChild(p)
	s.sendto(reply.build(), thing[id][1])
	# Generate cryptography keys
	gir = pow(int.from_bytes(gi, 'big'), r, DH_P)
	gir = gir.to_bytes(256, 'big').rjust(256, b'\x00')
	h = HMAC.new(ni + nr, gir, SHA256)
	skseed = h.digest()
	hs = ni + nr + id
	skd = HMAC.new(skseed, hs + b'\x01', SHA256).digest()
	skai = HMAC.new(skseed, skd + hs + b'\x02', SHA256).digest()
	skar = HMAC.new(skseed, skai + hs + b'\x03', SHA256).digest()
	skei = HMAC.new(skseed, skar + hs + b'\x04', SHA256).digest()
	sker = HMAC.new(skseed, skei + hs + b'\x05', SHA256).digest()
	skpi = HMAC.new(skseed, sker + hs + b'\x06', SHA256).digest()
	skpr = HMAC.new(skseed, skpi + hs + b'\x07', SHA256).digest()
	# Store keys in dictionary
	thing[id][2]["d"] = skd
	thing[id][2]["ai"] = skai
	thing[id][2]["ar"] = skar
	thing[id][2]["ei"] = skei
	thing[id][2]["er"] = sker
	thing[id][2]["pi"] = skpi
	thing[id][2]["pr"] = skpr
	print("Keys generated: ")
	print("ai: ", skai.hex())
	print("ar: ", skar.hex())
	print("ei: ", skei.hex())
	print("er: ", sker.hex())
	return IKE_AUTH

def auth(id, m: Message):
	reply = Message(id, IKE_AUTH, m.mid, True, False, [])
	return IKE_AUTH

def handle(id):
	stage = IKE_SA_INIT
	while True:
		if stage == IKE_AUTH:
			print(end="")
		m = Message.parse(recv(id))
		if m.exchange != stage:
			print("Wrong data")
			return
		if stage == IKE_SA_INIT:
			stage = sa_init(id, m)
		elif stage == IKE_AUTH:
			stage = auth(id, m)

def handle_catch(id):
	try:
		handle(id)
	except IKEException as e:
		if len(e.args[0]) == 2:
			n = NotifyPayload(*e.args[0])
		else:
			n = NotifyPayload(e.args[0][0], b'')
		nm = Message(id, e.args[1], e.args[2], True, False, [n]).build()
		s.sendto(nm, thing[id][1])
	print("deleting")
	del thing[id]

if __name__ == "__main__":
	while True:
		buf, a = s.recvfrom(65535)
		# buf = b'\x3a\x2e\xf8\xeb\xbf\x48\x72\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x02\x8c\x22\x00\x00\xf4\x02\x00\x00\x88\x01\x01\x00\x0f\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x01\x00\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80\x03\x00\x00\x08\x03\x00\x00\x0e\x03\x00\x00\x08\x03\x00\x00\x0d\x03\x00\x00\x08\x03\x00\x00\x0c\x03\x00\x00\x08\x03\x00\x00\x02\x03\x00\x00\x08\x02\x00\x00\x07\x03\x00\x00\x08\x02\x00\x00\x06\x03\x00\x00\x08\x02\x00\x00\x05\x03\x00\x00\x08\x02\x00\x00\x02\x03\x00\x00\x08\x04\x00\x00\x18\x03\x00\x00\x08\x04\x00\x00\x14\x03\x00\x00\x08\x04\x00\x00\x13\x03\x00\x00\x08\x04\x00\x00\x0e\x00\x00\x00\x08\x04\x00\x00\x05\x00\x00\x00\x68\x02\x01\x00\x0b\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x01\x00\x03\x00\x00\x0c\x01\x00\x00\x14\x80\x0e\x00\x80\x03\x00\x00\x08\x02\x00\x00\x07\x03\x00\x00\x08\x02\x00\x00\x06\x03\x00\x00\x08\x02\x00\x00\x05\x03\x00\x00\x08\x02\x00\x00\x02\x03\x00\x00\x08\x04\x00\x00\x18\x03\x00\x00\x08\x04\x00\x00\x14\x03\x00\x00\x08\x04\x00\x00\x13\x03\x00\x00\x08\x04\x00\x00\x0e\x00\x00\x00\x08\x04\x00\x00\x05\x28\x00\x01\x08\x00\x18\x00\x00\x69\x6c\x2d\x12\x82\x28\xec\x52\xcb\x21\xbd\x50\x56\x65\x5d\xd9\x49\x85\x4e\x6b\x6e\xe8\x2f\x87\x7a\x2a\x9f\x3d\xa6\xf9\x95\x31\x79\x58\x58\xea\xc4\x3c\x11\x2b\x3b\x79\x9e\x64\x2a\x90\xb3\x05\xea\x1a\x79\x04\x17\x5e\xa9\x95\xa6\x2d\xae\x1e\xa8\x0c\x6f\x18\x3d\x1c\x42\x2a\x7a\xed\x92\x2b\x98\x85\x9b\x18\x6c\xdc\x8f\xd3\x73\x44\x50\xdb\xe6\x8f\x0f\x2a\xaa\xf4\xb6\x0a\xa3\x49\xfc\x7b\x16\x27\x32\x92\x02\x60\xb3\xb1\x6c\x64\x56\xf1\xd8\x47\x22\xba\x25\x36\xd7\xa2\x95\x8f\x55\x89\x3e\xf5\xd9\xdc\x36\xa2\x04\xea\xbf\xca\x89\x26\x0e\x6f\x09\xea\x3d\xdc\x28\x91\x26\x35\x4a\x5a\xde\x40\x28\x04\x1b\x2e\x34\xb9\x07\x9b\xe2\xdd\xad\xa8\x17\x3e\xa1\xca\xc8\x0a\x5d\xa5\x47\xc1\xef\xb9\xf8\x65\x5d\x0c\x9a\x4c\x6b\xf3\x1f\xc1\x3d\xeb\xbc\x2f\x4c\x59\xf8\x51\x09\x3c\xaf\x9c\xfd\xf3\x0a\x8e\x5e\x3e\x86\xed\xba\x65\xcd\xd5\x4e\x6c\x75\xb9\xdc\xc1\x7a\xf1\x28\xa5\x99\xbd\xb9\x77\x27\x12\x4e\x69\x6f\x2a\x23\x84\x13\xa7\x5f\x1d\x8c\xf7\x40\x40\xf5\x8b\xe5\xa9\xec\x40\x59\xd0\x20\xc0\x2a\x5a\x8e\xfa\x31\x5c\xe5\x6c\x10\x00\xd8\x28\x29\x00\x00\x24\x80\x08\x3f\x07\x70\xd0\x4c\x0a\x9c\x1f\x38\x9d\xe0\x48\x2d\x59\x39\x89\x51\xc1\x4d\x85\xfe\x45\xd7\x3b\x6e\x35\xf9\xe6\x0f\xe1\x29\x00\x00\x1c\x00\x00\x40\x04\xc0\xda\x52\x87\xc2\xef\x53\x63\x0d\xfc\x70\xf2\x4a\x39\x40\x69\x99\xea\x3d\x37\x29\x00\x00\x1c\x00\x00\x40\x05\x8c\x1f\xda\x49\x5e\x45\x9a\xf0\x44\x70\x9a\x60\x3f\x56\x81\x13\xe2\xe6\xb1\xa6\x29\x00\x00\x10\x00\x00\x40\x2f\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00\x08\x00\x00\x40\x16'
		# a = ("::ffff:192.168.0.1", 21378)
		try:
			cid, sid = unpack_from("!QQ", buf, 0)
			id = buf[:16]
			if sid == 0:
				# New connection
				sid = randint(1, 0xffffffffffffffff)
				id = pack("!QQ", cid, sid)
				thing[id] = [[buf], a, {}]
				# handle(id)
				Thread(target=handle_catch, args=(id,), daemon=False).start()
			else:
				# Append to existing queue
				thing[id][0].append(buf)
				thing[id][1] = a
		except: pass
