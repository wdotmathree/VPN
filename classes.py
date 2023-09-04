from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from struct import pack, pack_into, unpack, unpack_from
import typing

from consts import *

payload_map: dict[int, type("Payload")] = {}

class Payload:
	def __init__(self, type: int, children: list["Payload"]):
		self.type = type
		self.children = children
		self.stale = True

	def addChildren(self, children: list["Payload"]):
		self.stale = True
		self.children += children

	def addChild(self, child: "Payload"):
		self.stale = True
		self.children.append(child)

	def build(self, nextid, curidx):
		if not self.stale:
			return self.buf

		buf = pack(
			"!BBH",
			nextid,
			0, # Critical bit is never set
			0xAAAA # Length placeholder
		)
		buf = bytearray(buf)
		for i, c in enumerate(self.children):
			buf += c.build(0 if i == len(self.children) - 1 else self.children[i + 1].type, i + 1)
		pack_into("!H", buf, 2, len(buf))
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes, ptype: int, id: bytes):
		res = []
		while len(buf):
			nexttype, critical, length = unpack_from("!BBH", buf)
			if ptype != IKEV2_PAYLOAD_ENCRYPTED and length > len(buf):
				raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX)
			if ptype in payload_map:
				if ptype == IKEV2_PAYLOAD_ENCRYPTED:
					res.append(payload_map[ptype].parse(buf[4:length], nexttype, id))
				res.append(payload_map[ptype].parse(buf[4:length], id))
			else:
				if critical & 0x80:
					raise IKEException(IKEV2_NOTIFY_CRITICAL_PAYLOAD)
			ptype = nexttype
			buf = buf[length:]
		return res


# Primitive payload type for raw data
class Raw(Payload):
	def __init__(self, data: bytes):
		self.data = data

	def build(self, nextid, curidx):
		assert nextid == 0
		return self.data


class SAPayload(Payload):
	children: list["Proposal"]

	def __init__(self, proposals: list["Proposal"]):
		super().__init__(IKEV2_PAYLOAD_SA, proposals)


	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		return cls(Payload.parse(buf, IKEV2_SUB_PROPOSAL, id))


class Proposal(Payload):
	children: list["Transform"]

	def __init__(self, num: int, protocol: int, transforms: list["Transform"]):
		self.num = num
		self.protocol = protocol
		super().__init__(IKEV2_SUB_PROPOSAL, transforms)

	def build(self, nextid, curidx):
		if not self.stale:
			return self.buf

		buf = pack(
			"!BxHBBBB",
			nextid,
			0xAAAA, # Length placeholder
			self.num,
			self.protocol,
			0x00, # SPI size
			len(self.children) # Number of transforms
		)
		buf = bytearray(buf)
		for i, c in enumerate(self.children):
			buf += c.build(0 if i == len(self.children) - 1 else self.children[i + 1].type, i + 1)
		pack_into("!H", buf, 2, len(buf))
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		num, protocol = unpack_from("!BB", buf)
		return cls(num, protocol, Payload.parse(buf[4:], IKEV2_SUB_TRANSFORM, id))


class Transform(Payload):
	children: list["Attribute"]

	def __init__(self, transtype: int, id: int, attributes: list["Attribute"]):
		self.transtype = transtype
		self.id = id
		super().__init__(IKEV2_SUB_TRANSFORM, attributes)

	def build(self, nextid, curidx):
		if not self.stale:
			return self.buf

		buf = pack(
			"!BxHBxH",
			nextid,
			0xAAAA, # Length placeholder
			self.transtype,
			self.id
		)
		buf = bytearray(buf)
		for c in self.children:
			buf += c.build()
		pack_into("!H", buf, 2, len(buf))
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		transtype, id = unpack_from("!BxH", buf)
		if len(buf) != 4:
			return cls(transtype, id, [Attribute.parse(buf[4:])])
		return cls(transtype, id, [])


class Attribute:
	def __init__(self, type: int, data: bytes):
		assert type == 14
		assert len(data) == 2
		self.type = type
		self.data = data

	def build(self):
		return pack("!H", 0x8000 | self.type) + self.data

	@classmethod
	def parse(cls, buf: bytes):
		if len(buf) != 4:
			raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX)
		type = unpack_from("!H", buf)[0] & 0x7fff
		data = buf[2:]
		return cls(type, data)


class KEPayload(Payload):
	children: list[Raw]

	def __init__(self, dh_group: int, data: bytes):
		self.dh_group = dh_group
		self.data = data
		super().__init__(IKEV2_PAYLOAD_KE, [Raw(data)])

	def build(self, nextid, curidx):
		if not self.stale:
			return self.buf

		buf = pack(
			"!BxHHxx",
			nextid,
			0xAAAA, # Length placeholder
			self.dh_group
		)
		buf = bytearray(buf)
		buf += self.children[0].build(0, 0)
		pack_into("!H", buf, 2, len(buf))
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		if len(buf) < 4:
			raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX)
		dh_group, = unpack_from("!H", buf)
		data = buf[4:]
		return cls(dh_group, data)


class NoncePayload(Payload):
	def __init__(self, data: bytes):
		self.data = data
		super().__init__(IKEV2_PAYLOAD_NONCE, [Raw(data)])

	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		return cls(buf)


class NotifyPayload(Payload):
	def __init__(self, type: int, msg: bytes):
		buf = b'\x00\x00' + pack("!H", type) + msg
		super().__init__(IKEV2_PAYLOAD_NOTIFY, [Raw(buf)])

	@classmethod
	def parse(cls, buf: bytes, id: bytes):
		if len(buf) < 4:
			raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX)
		type, = unpack_from("!H", buf, 2)
		msg = buf[4:]
		return cls(type, msg)


class EncryptedPayload(Payload):
	def __init__(self, id: bytes, children: list["Payload"]):
		self.id = id
		super().__init__(IKEV2_PAYLOAD_ENCRYPTED, children)

	def build(self, nextid, curidx):
		assert nextid == 0
		if len(self.children) == 0:
			fid = 0
		else:
			fid = self.children[0].type
		buf = pack(
			"!BxH",
			fid,
			0xAAAA # Length placeholder
		)
		buf = bytearray(buf)
		with open("/dev/urandom", "rb") as f:
			iv = f.read(16)
		buf += iv
		p = bytearray()
		for i, c in enumerate(self.children):
			p += c.build(0 if i == len(self.children) - 1 else self.children[i + 1].type, i + 1)
		print(len(p))
		pad = -(len(p) + 1) % 16
		with open("/dev/urandom", "rb") as f:
			extra = f.read(1)[0] & 0xf0
		with open("/dev/urandom", "rb") as f:
			p += f.read(pad + extra)
		p += pack("!B", pad + extra)
		p = AES.new(thing[self.id][2]['er'], AES.MODE_CBC, iv).encrypt(p)
		buf += p
		pack_into("!H", buf, 2, len(buf) + 16)
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes, nextid: int, id: bytes):
		iv = buf[:16]
		buf = buf[16:]
		buf = AES.new(thing[id][2]['ei'], AES.MODE_CBC, iv).decrypt(buf)
		pad = buf[-1]
		buf = buf[:-pad]
		return cls(id, Payload.parse(buf, nextid, id))


payload_map = {
	IKEV2_PAYLOAD_SA: SAPayload,
	IKEV2_SUB_PROPOSAL: Proposal,
	IKEV2_SUB_TRANSFORM: Transform,
	IKEV2_PAYLOAD_KE: KEPayload,
	IKEV2_PAYLOAD_NONCE: NoncePayload,
	IKEV2_PAYLOAD_NOTIFY: NotifyPayload,
	IKEV2_PAYLOAD_ENCRYPTED: EncryptedPayload,
}

class Message:
	def __init__(self, id: bytes, exchange: int, mid: int, response: bool, initiator: bool, children: list[Payload]):
		self.id = id
		self.exchange = exchange
		self.mid = mid
		self.children = children
		self.flags = (response << 5) | (initiator << 3)
		self.stale = True

	def addChildren(self, children: list[Payload]):
		self.stale = True
		self.children += children

	def addChild(self, child: Payload):
		self.stale = True
		self.children.append(child)

	def build(self):
		if not self.stale:
			return self.buf

		nextpayload = 0
		if len(self.children):
			nextpayload = self.children[0].type
		buf = pack(
			"!16sBBBBLL",
			self.id,
			nextpayload,
			0x20, # Protocol version
			self.exchange,
			self.flags,
			self.mid,
			0xAAAAAAAA # Length placeholder
		)
		buf = bytearray(buf)
		for i, c in enumerate(self.children):
			buf += c.build(0 if i == len(self.children) - 1 else self.children[i + 1].type, i + 1)
		pack_into("!L", buf, 24, len(buf))

		if self.children[-1].type == IKEV2_PAYLOAD_ENCRYPTED:
			buf += HMAC.new(thing[self.id][2]['ar'], buf, SHA256).digest()[:16]

		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes):
		id, nextpayload, version, exchange, flags, mid, length = unpack_from("!16sBBBBLL", buf)
		try:
			if version != 0x20:
				raise IKEException(IKEV2_NOTIFY_INVALID_VERSION, b'\x20')
			if length != len(buf):
				raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX)
			encrypted = nextpayload == IKEV2_PAYLOAD_ENCRYPTED
			if not encrypted:
				i = 28
				while i < length:
					if buf[i] == 0:
						break
					elif buf[i] == IKEV2_PAYLOAD_ENCRYPTED:
						encrypted = True
						break
					i += unpack_from("!H", buf, i + 2)[0]
			if encrypted:
				# Verify MAC
				mac = buf[-16:]
				buf = buf[:-16]
				if HMAC.new(thing[id][2]['ai'], buf, SHA256).digest()[:16] != mac:
					raise IKEException(IKEV2_NOTIFY_INVALID_SYNTAX, b'')

			res = cls(id, exchange, mid, flags & 0x20 != 0, flags & 0x08 != 0, [])
			res.children += Payload.parse(buf[28:], nextpayload, id)
				
			return res
		except IKEException as e:
			raise IKEException(e.args, exchange, mid)
