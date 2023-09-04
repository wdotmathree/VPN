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
	def parse(cls, buf: bytes, ptype: int):
		res = []
		while len(buf):
			nexttype, critical, length = unpack_from("!BBH", buf)
			if length > len(buf):
				raise ValueError("Length mismatch")
			if ptype in payload_map:
				res.append(payload_map[ptype].parse(buf[4:length]))
			else:
				if critical & 0x80:
					raise PayloadException("Unknown critical payload")
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
	def __init__(self, proposals: list["Proposal"]):
		super().__init__(IKEV2_PAYLOAD_SA, proposals)


	@classmethod
	def parse(cls, buf: bytes):
		return cls(Payload.parse(buf, IKEV2_SUB_PROPOSAL))


class Proposal(Payload):
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
	def parse(cls, buf: bytes):
		num, protocol = unpack_from("!BB", buf)
		return cls(num, protocol, Payload.parse(buf[4:], 3))


class Transform(Payload):
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
	def parse(cls, buf: bytes):
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
			raise ValueError("Length mismatch")
		type = unpack_from("!H", buf)[0] & 0x7fff
		data = buf[2:]
		return cls(type, data)


class KEPayload(Payload):
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
	def parse(cls, buf: bytes):
		if len(buf) < 4:
			raise ValueError("Length mismatch")
		dh_group, = unpack_from("!H", buf)
		data = buf[4:]
		return cls(dh_group, data)


class NoncePayload(Payload):
	def __init__(self, data: bytes):
		self.data = data
		super().__init__(IKEV2_PAYLOAD_NONCE, [Raw(data)])

	@classmethod
	def parse(cls, buf: bytes):
		return cls(buf)


class NotifyPayload(Payload):
	def __init__(self, type: int, msg: bytes):
		buf = b'\x00\x00' + pack("!H", type) + msg
		super().__init__(IKEV2_PAYLOAD_NOTIFY, [Raw(buf)])

	@classmethod
	def parse(cls, buf: bytes):
		if len(buf) < 4:
			raise ValueError("Length mismatch")
		type, = unpack_from("!H", buf, 2)
		msg = buf[4:]
		return cls(type, msg)


payload_map = {
	IKEV2_PAYLOAD_SA: SAPayload,
	IKEV2_SUB_PROPOSAL: Proposal,
	IKEV2_SUB_TRANSFORM: Transform,
	IKEV2_PAYLOAD_KE: KEPayload,
	IKEV2_PAYLOAD_NONCE: NoncePayload,
	IKEV2_PAYLOAD_NOTIFY: NotifyPayload,
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
		buf = bytes(buf)

		self.buf = buf
		self.stale = False
		return buf

	@classmethod
	def parse(cls, buf: bytes):
		id, nextpayload, version, exchange, flags, mid, length = unpack_from("!16sBBBBLL", buf)
		if version != 0x20:
			raise VersionMismatch(version)
		if length != len(buf):
			raise ValueError("Length mismatch")
		res = cls(id, exchange, mid, flags & 0x20 != 0, flags & 0x08 != 0, [])
		res.children += Payload.parse(buf[28:], nextpayload)
		return res
