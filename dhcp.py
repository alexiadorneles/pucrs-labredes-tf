import binascii
import socket
import struct

class DHCP(object):
	def __init__(self, packet, length):
		self._payload = packet#[42:]
		self._length = length
		self._ciaddr = ''
		self._chaddr = ''
		self._option_55 = ''
		self._option_53 = ''
		self._option_12 = ''
		self._option_50 = ''
		self._option_54 = ''
		self._transaction_id = ''
	def parse_payload(self):
		# parse DHCP payload [0:44]
		#    ciaddr [Client IP Address]      : [12:16]
		#    yiaddr [Your IP Address]        : [16:20]
		#    siaddr [Server IP Address]      : [20:24]
		#    giaddr [Gateway IP Address]     : [24:28]
		#    chaddr [Client Hardware address]: [28:44]
		tmp = struct.unpack('!4s', self._payload[12:16])
		self._ciaddr = socket.inet_ntoa(tmp[0])
		self._chaddr = binascii.hexlify(self._payload[28:34]).decode()


	# DHCP options format:
	#     Magic Cookie + DHCP options + FF(end option)
	#     DHCP option format:
	#         code(1 byte) + length(1 byte) + value
	#     Pad and End option format:
	#         code(1 byte)
	def parse_options(self):
		find = False
		payload = binascii.hexlify(self._payload).decode()
		self._transaction_id = bytes.fromhex(payload[8:16])
		index = payload.find(DHCP_Protocol.magic_cookie)
		if -1 == index:
			return

		index += len(DHCP_Protocol.magic_cookie)
		hex_count = self._length * 2;
		while True:
			code = int(payload[index:index+2], 16)
			if DHCP_Protocol.option_pad == code:
				index += 2
				continue
			if DHCP_Protocol.option_end == code:
				return
			length = int(payload[index+2:index+4], 16)
			value = payload[index+4:index+4+length*2]

			# set DHCP options
			if DHCP_Protocol.option_request_list == code:
				self._option_55 = value
			elif DHCP_Protocol.option_message_type == code:
				self._option_53 = DHCP_Protocol.get_message_type(int(value))
			elif DHCP_Protocol.option_host_name == code:
				self._option_12 = bytes.fromhex(value).decode()
			elif DHCP_Protocol.option_request_ip == code:
				b = bytes.fromhex(value)
				self._option_50 = socket.inet_ntoa(b)
			elif DHCP_Protocol.option_server_id == code:
				b = bytes.fromhex(value)
				self._option_54 = socket.inet_ntoa(b)

			index = index + 4 + length * 2

			if index + 4 >  hex_count:
				break

	@property
	def ciaddr(self):
		return self._ciaddr

	@property
	def chaddr(self):
		return self._chaddr

	@property
	def option_55(self):
		return self._option_55

	@property
	def option_53(self):
		return self._option_53

	@property
	def option_12(self):
		return self._option_12

	@property
	def option_50(self):
		return self._option_50

	@property
	def option_54(self):
		return self._option_54
	@property
	def transaction_id(self):
		return self._transaction_id

class DHCP_Protocol(object):
	server_port = 67
	client_port = 68

	# DHCP options
	magic_cookie        = '63825363'
	option_pad          = 0
	option_host_name    = 12
	option_request_ip   = 50
	option_message_type = 53
	option_server_id    = 54
	option_request_list = 55
	option_end          = 255

	@staticmethod
	def get_message_type(value):
		message_type = {
			1: 'DHCPDISCOVER',
			2: 'DHCPOFFER',
			3: 'DHCPREQUEST',
			4: 'DHCPDECLINE',
			5: 'DHCPACK',
			6: 'DHCPNAK',
			7: 'DHCPRELEASE',
			8: 'DHCPINFORM'
		}
		return message_type.get(value, 'None')
