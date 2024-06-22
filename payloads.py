import socket
import binascii
from enum import Enum

class DHCPPayload:
    def __init__(self, 
                 opt, 
                 htype,
                 hlen,
                 hops,
                 trans_id,
                 se,
                 flags,
                 ciaddr,
                 yiaddr,
                 siaddr,
                 giaddr,
                 chaddr,
                 chaddr_padding,
                 sname,
                 bname,
                 mcookie, 
                 option):
                #  option_53,
                #  option_51,
                #  option_1,
                #  option_3,
                #  option_6,
                #  option_54,
                #  option_125,
                #  option_58,
                #  option_59,
                #  option_28,
                #  option_255):
        self._opt = opt
        self._htype = htype
        self._hlen = hlen
        self._hops = hops
        self._trans_id = trans_id
        self._se = se
        self._flags = flags
        self._ciaddr = ciaddr
        self._yiaddr = yiaddr
        self._siaddr = siaddr
        self._giaddr = giaddr
        self._chaddr = chaddr
        self._chaddr_padding = chaddr_padding
        self._sname = sname
        self._bname = bname
        self._mcookie = mcookie
        self._option = option
        # self._option_53 = option_53
        # self._option_51 = option_51
        # self._option_1 = option_1
        # self._option_3 = option_3
        # self._option_6 = option_6
        # self._option_54 = option_54
        # self._option_125 = option_125
        # self._option_58 = option_58
        # self._option_59 = option_59
        # self._option_28 = option_28
        # self._option_255 = option_255

    def get_bytes(self):
        return ( self._opt.to_bytes(1, 'little')
            + self._htype.to_bytes(1, 'little')
            + self._hlen.to_bytes(1, 'little')
            + self._hops.to_bytes(1, 'little')
            + self._trans_id + self._se.to_bytes(2, 'little')
            + self._flags.to_bytes(2, 'little')
            + socket.inet_pton(socket.AF_INET, self._ciaddr)
            + socket.inet_pton(socket.AF_INET, self._yiaddr)
            + socket.inet_pton(socket.AF_INET, self._siaddr)
            + socket.inet_pton(socket.AF_INET, self._giaddr)
            + binascii.unhexlify(self._chaddr)
            + binascii.unhexlify(self._chaddr_padding)
            + binascii.unhexlify(self._sname)
            + binascii.unhexlify(self._bname) 
            + binascii.unhexlify(self._mcookie)
            + Options.get_options_by_package(self._option)
            # + binascii.unhexlify(self._option_53) 
            # + b'04' + binascii.unhexlify(self._option_51)
            # + b'04' + binascii.unhexlify(self._option_1)

            )
            
class EthernetPayload:
	def __init__(self, destination, source, type):
		self._destination = destination
		self._source = source
		self._type = type

class IPV4Payload:
    def __init__(self, version, hl, tos, identification, flags, ttl, protocol, header_checksum, source, destination, ip_option):
        self._version = version
        self._hl = hl
        self._tos = tos
        self._identification = identification
        self._flags = flags
        self._ttl = ttl
        self._protocol = protocol
        self._header_checksum = header_checksum
        self._source = source
        self._destination = destination
        self._ip_option = ip_option


class Options(Enum):
    OFFER = 'offer'
    ACK = 'ack'

    @staticmethod
    def get_options_by_package(option):
        if option == Options.OFFER:
            return Options.get_offer_options()
        elif option == Options.ACK:
            return Options.get_ack_options()
        return 

    @staticmethod
    def get_offer_options():
        return (binascii.unhexlify(Options.option_53_offer() + Options.option_51() + Options.option_1() + Options.option_59())
            + Options.option_3() + Options.option_6() + Options.option_54() + Options.option_28() + Options.option_255()
        )
    
    @staticmethod
    def get_ack_options():
        return (binascii.unhexlify(Options.option_53_ack() + Options.option_51() + Options.option_1() + Options.option_59())
            + Options.option_3() + Options.option_6() + Options.option_54() + Options.option_28() + Options.option_255()
        )
    
    @staticmethod
    def option_53_offer():
        return '350102'

    @staticmethod
    def option_53_ack():
        return '350105'

    @staticmethod
    def option_51():
        return '330400003840'
    
    @staticmethod
    def option_3():
        return binascii.unhexlify('0304') + Options.get_ip()
    
    @staticmethod
    def option_6():
        return binascii.unhexlify('0604') + Options.get_ip()

    @staticmethod
    def option_54():
        return binascii.unhexlify('3604') + Options.get_ip()

    @staticmethod
    def option_28():
        return binascii.unhexlify('1c04') + Options.get_broadcast_ip()

    @staticmethod
    def option_255():
        return binascii.unhexlify('ff')

    @staticmethod
    def option_59():
        return '3b0400003138'

    @staticmethod
    def option_1():
        return '0104ffffff00'

    @staticmethod
    def get_broadcast_ip():
        return socket.inet_pton(socket.AF_INET, '192.168.15.255')
    
    @staticmethod
    def get_ip():
        return socket.inet_pton(socket.AF_INET, '192.168.15.10')#socket.gethostbyname(socket.gethostname()))