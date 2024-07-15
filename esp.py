# Very bad ESP server implementation

from Crypto.Cipher import AES
# from Crypto.Hash import SHA256, HMAC
from threading import Thread
from time import sleep

import os
import socket

import classes
import consts

s: socket = None
thing = {} # idi: [in_q, a, k, idr, ikeid]


def recv(id):
	while len(thing[id]['in_q']) == 0:
		sleep(0.1)
	return thing[id]['in_q'].pop(0)


def handleIncomingData(id):
	while True:
		buf = recv(id)
		iv = buf[8:24]
		# icv = buf[-16:]
		enc = buf[24:-16]
		# Verify ICV
		# TODO: Implement
		# Decrypt
		dec = AES.new(thing[id]['ek'], AES.MODE_CBC, iv).decrypt(enc)
		# Check next header and remove padding
		nextHead = dec[-1]
		padlen = dec[-2]
		dec = dec[:-(padlen + 2)]

		# Pass to transport layer processing
		# TODO: Implement


def handleIncomingData_catch(id):
	try:
		handleIncomingData(id)
	except consts.ESPException as e:
		if len(e.args[0]) == 2:
			n = classes.NotifyPayload(*e.args[0])
		else:
			n = classes.NotifyPayload(e.args[0][0], b'')
		if len(thing[id][2]):
			n = classes.EncryptedPayload(id, [n])
		nm = classes.Message(id, e.args[1], e.args[2], True, False, [n]).build()
		misoq.append((nm, thing[id]['a']))
	print("deleting")
	del thing[id]


def main(misoq_in, mosiq_in, _):
	global s, misoq, mosiq
	if os.getuid():
		s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
		s.bind(("::", 5000))
	else:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
	s.setblocking(0)
	misoq, mosiq = misoq_in, mosiq_in

	while True:
		try:
			for msg in mosiq:
				print('recieved msg')
				thing[msg['ispi']] = {'in_q': [], 'a': None, 'ek': msg['ek'], 'ak': msg['ak'], 'idr': msg['rspi'], 'ikeid': msg['id']}
				Thread(target=handleIncomingData_catch, args=(msg['ispi'],), daemon=True).start()
			for i in range(len(mosiq)):
				mosiq.pop()
			buf, a = s.recvfrom(65535)
			buf = buf[20:]
			id = buf[:4]
			if id in thing:
				# Append to existing queue
				thing[id]['in_q'].append(buf)
				thing[id]['a'] = a
		except BlockingIOError:
			sleep(0.01)
