# Very bad ESP server implementation

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from queue import Queue, Empty
from threading import Thread
from time import sleep
from typing import Any, Union

import os
import socket

import classes


s: socket = None
thing: dict[bytes, dict[bytes, Union[Queue, bytes]]] = None # idi: [in_q, a, ek, ak, idr, ikeid, iseq, rseq]

misoq: Queue[tuple[bytes, tuple[str, int]]] = None # Message queue for IKE messages from esp.py
mosiq: Queue[dict[str, Any]] = None # Message queue for message from ike.py
forwardq: Queue[tuple[bytes, int, bytes]] = None # Message queue for message from esp.py to forward.py


def recv(id):
	return thing[id]['in_q'].get()


def handleIncomingData(id):
	while True:
		buf = recv(id)
		thing[id]['iseq'] = max(thing[id]['iseq'], int.from_bytes(buf[4:8], 'big'))
		iv = buf[8:24]
		# icv = buf[-16:]
		enc = buf[24:-16]
		# Verify ICV
		icv = HMAC.new(thing[id]['ak'], buf[:-16], digestmod=SHA256).digest()[:16]
		if icv != buf[-16:]:
			print("merde")
			raise classes.ESPException((classes.NotifyPayload(1, b''), 0, 0), 1, 0)
		# Decrypt
		dec = AES.new(thing[id]['ek'], AES.MODE_CBC, iv).decrypt(enc)
		# Check next header and remove padding
		nextHead = dec[-1]
		padlen = dec[-2]
		dec = dec[:-(padlen + 2)]
		if nextHead == 59: # Dummy packet
			continue

		# Pass to transport layer processing
		forwardq.put((id, nextHead, dec))


def handleIncomingData_catch(id):
	try:
		handleIncomingData(id)
	except classes.ESPException as e:
		if len(e.args[0]) == 2:
			n = classes.NotifyPayload(*e.args[0])
		else:
			n = classes.NotifyPayload(e.args[0][0], b'')
		if len(thing[id][2]):
			n = classes.EncryptedPayload(id, [n])
		nm = classes.Message(id, e.args[1], e.args[2], True, False, [n]).build()
		misoq.put((nm, thing[id]['a']))
	print("deleting")
	del thing[id]


def main(misoq_in, mosiq_in, thing_in, forwardq_in):
	global s, misoq, mosiq, thing, forwardq
	if os.getuid():
		s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
		s.bind(("::", 5000))
	else:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
	s.setblocking(0)
	misoq, mosiq, thing, forwardq = misoq_in, mosiq_in, thing_in, forwardq_in

	while True:
		try:
			try:
				msg = mosiq.get_nowait()
			except Empty:
				msg = None
			while msg is not None:
				thing[msg['ispi']] = {
					'in_q': Queue(),
					'a': None,
					'ek': msg['ek'],
					'ak': msg['ak'],
					'idr': msg['rspi'],
					'ikeid': msg['id'],
					'iseq': 0,
					'rseq': 0,
				}
				Thread(target=handleIncomingData_catch, args=(msg['ispi'],), daemon=True).start()
				try:
					msg = mosiq.get_nowait()
				except Empty:
					break
			buf, a = s.recvfrom(65535)
			buf = buf[20:]
			id = buf[:4]
			if id in thing:
				# Append to existing queue
				thing[id]['in_q'].put(buf)
				thing[id]['a'] = a
		except BlockingIOError:
			sleep(0.001)
