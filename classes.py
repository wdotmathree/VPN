from struct import pack, pack_into

class Payload:
	def __init__(self, type: int, children: list["Payload"]):
		self.type = type
		self.children = children
		self.stale = True

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


class Raw(Payload):
	def __init__(self, data: bytes):
		self.data = data

	def build(self, nextid, curidx):
		assert nextid == 0
		return self.data


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
