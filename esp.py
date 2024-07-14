# Very bad ESP server implementation

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from socket import *
from threading import Thread
from time import sleep

import os

from classes import *
from consts import *

s: socket = None
thing = {} # idi: [q, a, k, idr, ikeid]

def recv(id):
	while len(thing[id]['q']) == 0:
		sleep(0.1)
	return thing[id]['q'].pop(0)

def handle(id):
	s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
	s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
	s.bind(("0.0.0.0", 0))
	b = b''
	while True:
		buf = recv(id)
		iv = buf[8:24]
		icv = buf[-16:]
		enc = buf[24:-16]
		# Verify ICV
		# TODO: Implement
		# Decrypt
		dec = AES.new(thing[id]['ek'], AES.MODE_CBC, iv).decrypt(enc)
		# Check next header and remove padding
		nextHead = dec[-1]
		padlen = dec[-2]
		print(nextHead)
		dec = dec[:-(padlen + 2)]
		print(dec, dec[20:])

		# Send message to transport layer processing
		# TODO: Implement

def handle_catch(id):
	try:
		handle(id)
	except ESPException as e:
		if len(e.args[0]) == 2:
			n = NotifyPayload(*e.args[0])
		else:
			n = NotifyPayload(e.args[0][0], b'')
		if len(thing[id][2]):
			n = EncryptedPayload(id, [n])
		nm = Message(id, e.args[1], e.args[2], True, False, [n]).build()
		misoq.append((nm, thing[id]['a']))
	print("deleting")
	del thing[id]

def main(misoq_in, mosiq_in, _):
	global s, misoq, mosiq
	if os.getuid():
		s = socket(AF_INET6, SOCK_DGRAM)
		s.bind(("::", 5000))
	else:
		s = socket(AF_INET, SOCK_RAW, IPPROTO_ESP)
	s.setblocking(0)
	misoq, mosiq = misoq_in, mosiq_in

	while True:
		try:
			for msg in mosiq:
				print('recieved msg')
				thing[msg['ispi']] = {'q': [], 'a': None, 'ek': msg['ek'], 'ak': msg['ak'], 'idr': msg['rspi'], 'ikeid': msg['id']}
				Thread(target=handle_catch, args=(msg['ispi'],), daemon=True).start()
			for i in range(len(mosiq)):
				mosiq.pop()
			buf, a = s.recvfrom(65535)
			buf = buf[20:]
			id = buf[:4]
			if id in thing:
				# Append to existing queue
				thing[id]['q'].append(buf)
				thing[id]['a'] = a
		except BlockingIOError: sleep(0.01)
