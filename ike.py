# Very bad IKEv2 server implementation

from queue import Queue, Empty
from random import randint
from socket import socket, AF_INET6, SOCK_DGRAM
from struct import pack, unpack_from
from threading import Thread
from time import sleep
from typing import Any
from Crypto.Hash import SHA256, HMAC

import os

import classes
import consts

s: socket = None

misoq: list[tuple[bytes, tuple[str, int]]] = None # Message queue for IKE messages from esp.py
mosiq: list[dict[str, Any]] = None # Message queue for message from ike.py
thing: dict[bytes, tuple[list[bytes]]] = {}


def recv(id):
	try:
		return thing[id]['q'].get()
	except KeyError:
		return b''


def sendNotification(id, exchange, mid, type, msg):
	d = b'\x00\x00' + pack("!H", type) + msg # Notify payload + notification data
	p = classes.Payload(consts.IKEV2_PAYLOAD_NOTIFY, [classes.Raw(d)]) # Notify payload + header
	msg = classes.Message(id, exchange, mid, True, False, [p]).build() # Message header + notify payload
	s.sendto(msg, thing[id]['a'])


def parseProposalInit(proposal: classes.Proposal):
	num = 0
	for t in proposal.children:
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


def parseProposalAuth(proposal: classes.Proposal):
	num = 0
	for t in proposal.children:
		if t.transtype == 1: # Encryption
			if t.id == 12: # AES-CBC
				if t.children[0].data == b'\x01\x00':
					num += 1
		elif t.transtype == 3: # Integrity
			if t.id == 12: # HMAC-SHA256-128
				num += 1
	return num >= 2


def sa_initStage(id, m: classes.Message):
	reply = classes.Message(id, consts.IKE_SA_INIT, m.mid, True, False, [])
	gi = None
	ni = None
	r = None
	gr = None
	nr = None
	rsig = None
	isig = m.build()
	with open("/dev/urandom", "rb") as f:
		r = f.read(256)
		nr = f.read(32)
	isig += nr
	r = int.from_bytes(r, 'big')
	gr = pow(2, r, consts.DH_P).to_bytes(256, 'big').rjust(256, b'\x00')
	for p in m.children:
		if p.type == consts.IKEV2_PAYLOAD_SA:
			# Look for supported stuff
			success = 0
			for proposal in p.children:
				if parseProposalInit(proposal):
					success = proposal.num
					break
			if not success:
				raise classes.IKEException((consts.IKEV2_NOTIFY_NO_PROPOSAL, b''), m.exchange, m.mid)
			# Build reply
			p = classes.SAPayload([classes.Proposal(success, 1, b'', [
				classes.Transform(1, 12, [classes.Attribute(14, b'\x01\x00')]),
				classes.Transform(3, 12, []),
				classes.Transform(2, 5, []),
				classes.Transform(4, 14, [])
			])])
			reply.addChild(p)
		elif p.type == consts.IKEV2_PAYLOAD_KE:
			if p.dh_group != 14:
				raise classes.IKEException((consts.IKEV2_NOTIFY_INVALID_KE_PAYLOAD, b'\x00\x0e'), m.exchange, m.mid) # We only accept group 14
			gi = p.children[0].data
			# Build reply
			p = classes.KEPayload(14, gr)
			del gr
			reply.addChild(p)
		elif p.type == consts.IKEV2_PAYLOAD_NONCE:
			ni = p.children[0].data
			rsig = ni
			# Build reply
			p = classes.NoncePayload(nr)
			reply.addChild(p)
	s.sendto(reply.build(), thing[id]['a'])
	rsig = reply.build() + rsig
	# Generate cryptography keys
	gir = pow(int.from_bytes(gi, 'big'), r, consts.DH_P)
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
	thing[id]['d'] = skd
	thing[id]['ai'] = skai
	thing[id]['ar'] = skar
	thing[id]['ei'] = skei
	thing[id]['er'] = sker
	thing[id]['pi'] = skpi
	thing[id]['pr'] = skpr
	thing[id]['rsig'] = rsig
	thing[id]['isig'] = isig
	thing[id]['ni'] = ni
	thing[id]['nr'] = nr
	print("Keys generated: ")
	print("ei: ", skei.hex())
	print("er: ", sker.hex())
	print("ai: ", skai.hex())
	print("ar: ", skar.hex())
	return consts.IKE_AUTH


def authStage(id, m: classes.Message):
	if len(m.children) != 1 or m.children[0].type != consts.IKEV2_PAYLOAD_ENCRYPTED:
		raise classes.IKEException((consts.IKEV2_NOTIFY_INVALID_SYNTAX, b''), m.exchange, m.mid)
	reply = classes.Message(id, consts.IKE_AUTH, m.mid, True, False, [classes.EncryptedPayload(id, [])])
	username = None
	iauthdata = None
	rsig = thing[id]['rsig']
	isig = thing[id]['isig']
	for p in m.children[0].children:
		if p.type == consts.IKEV2_PAYLOAD_IDI:
			username = p.children[0].data
			idi = p.build(consts.IKEV2_PAYLOAD_AUTH, 0)
			isig += HMAC.new(thing[id]['pi'], idi[4:], SHA256).digest()
			# Build reply
			p = classes.IdentityPayload(consts.IKEV2_PAYLOAD_IDR, consts.IKEV2_ID_KEY_ID, b'Server')
			rsig += HMAC.new(thing[id]['pr'], p.build(consts.IKEV2_PAYLOAD_AUTH, 0)[4:], SHA256).digest()
			reply.children[0].addChild(p)
		elif p.type == consts.IKEV2_PAYLOAD_AUTH:
			iauthdata = p.children[0].data
			sigkey = HMAC.new(b'PASSWORD', b'Key Pad for IKEv2', SHA256).digest()
			rsig = HMAC.new(sigkey, rsig, SHA256).digest()
			isig = HMAC.new(sigkey, isig, SHA256).digest()
			if iauthdata != isig:
				raise classes.IKEException((consts.IKEV2_NOTIFY_INVALID_SYNTAX, b"signature doesn't match"), m.exchange, m.mid)
			# Build reply
			p = classes.AuthPayload(consts.IKEV2_AUTH_SHARED_KEY_MIC, rsig)
			reply.children[0].addChild(p)
		elif p.type == consts.IKEV2_PAYLOAD_SA: # 100% copied from sa_init
			# Look for supported stuff
			success = 0
			for proposal in p.children:
				if parseProposalAuth(proposal):
					success = proposal.num
					break
			if not success:
				raise classes.IKEException((consts.IKEV2_NOTIFY_NO_PROPOSAL, b''), m.exchange, m.mid)
			# Build reply
			thing[id]['espspir'] = p.children[0].spi
			spi = pack("!L", randint(1, 0xffffffff))
			thing[id]['espspii'] = spi
			p = classes.SAPayload([classes.Proposal(success, 3, spi, [
				classes.Transform(1, 12, [classes.Attribute(14, b'\x01\x00')]),
				classes.Transform(3, 12, []),
				classes.Transform(5, 0, [])
			])])
			reply.children[0].addChild(p)
	# Manually add global traffic selectors
	tmp = classes.Raw(b'\x2d\x00\x00\x18\x01\x00\x00\x00\x07\x06\x00\x10\x00\x00\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x18\x01\x00\x00\x00\x07\x06\x00\x10\x00\x00\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff')
	tmp.type = 44
	reply.children[0].addChild(tmp)
	# reply.children = reply.children[0].children
	s.sendto(reply.build(), thing[id]['a'])

	# Generate ESP keys
	espekey = HMAC.new(thing[id]['d'], thing[id]['ni'] + thing[id]['nr'] + b'\x01', SHA256).digest()
	espakey = HMAC.new(thing[id]['d'], espekey + thing[id]['ni'] + thing[id]['nr'] + b'\x02', SHA256).digest()
	print("ESP keys:")
	print("e: ", espekey.hex())
	print("a: ", espakey.hex())
	# Send message to ESP module
	mosiq.put({'ispi': thing[id]['espspii'], 'rspi': thing[id]['espspir'], 'ek': espekey, 'ak': espakey, 'id': id})
	return consts.IKE_IDLE


def resolveIkeStatus(id, m: classes.Message):
	if m.exchange == consts.IKE_INFORMATIONAL:
		for p in m.children[0].children:
			if p.type == consts.IKEV2_PAYLOAD_DELETE:
				if p.protocol == 1: # IKE
					return consts.IKE_DELETED
	# TODO: Figure out what to do
	return consts.IKE_IDLE # No-op because not implemented


def handleIkeMessage(id):
	stage = consts.IKE_SA_INIT
	while stage != consts.IKE_DELETED:
		buf = recv(id)
		if len(buf) == 0:
			return
		m = classes.Message.parse(buf)
		# if len(m.children) >= 1 and m.children[0].type == IKEV2_PAYLOAD_ENCRYPTED:
		# 	tmp = deepcopy(m)
		# 	tmp.children = tmp.children[0].children
		# 	s.sendto(tmp.build(), ("::ffff:192.168.0.1", 500))
		if stage != consts.IKE_IDLE and m.exchange != stage:
			print("Wrong data")
			raise classes.IKEException((consts.IKEV2_NOTIFY_INVALID_SYNTAX, b''), m.exchange, m.mid)
		if stage == consts.IKE_SA_INIT:
			stage = sa_initStage(id, m)
		elif stage == consts.IKE_AUTH:
			stage = authStage(id, m)
		elif stage == consts.IKE_IDLE:
			stage = resolveIkeStatus(id, m)


def handleIkeMessage_catch(id):
	try:
		handleIkeMessage(id)
	except classes.IKEException as e:
		if len(e.args[0]) == 2:
			n = classes.NotifyPayload(*e.args[0])
		else:
			n = classes.NotifyPayload(e.args[0][0], b'')
		if len(thing[id]) > 2:
			n = classes.EncryptedPayload(id, [n])
		nm = classes.Message(id, e.args[1], e.args[2], True, False, [n]).build()
		s.sendto(nm, thing[id]['a'])
	print("deleting")
	del thing[id]


def main(misoq_in, mosiq_in):
	global s, misoq, mosiq
	s = socket(AF_INET6, SOCK_DGRAM)
	s.bind(("::", 4500 if os.getuid() else 500))
	s.setblocking(0)
	misoq, mosiq = misoq_in, mosiq_in
	classes.init_classes(thing)

	while True:
		try:
			try:
				msg = misoq.get_nowait()
			except Empty:
				msg = None
			while msg is not None:
				s.sendto(*msg)
				try:
					msg = misoq.get_nowait()
				except Empty:
					break
			buf, a = s.recvfrom(65535)
			cid, sid = unpack_from("!QQ", buf, 0)
			id = buf[:16]
			if sid == 0:
				# New connection
				sid = randint(1, 0xffffffffffffffff)
				id = pack("!QQ", cid, sid)
				q = Queue()
				q.put(buf)
				thing[id] = {'q': q, 'a': a}
				Thread(target=handleIkeMessage_catch, args=(id,), daemon=True).start()
			else:
				# Append to existing queue
				thing[id]['q'].put(buf)
				thing[id]['a'] = a
		except BlockingIOError:
			sleep(0.001)
