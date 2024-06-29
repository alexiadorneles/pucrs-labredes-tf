import socket
import binascii
from enum import Enum

class DHCPFrame:
    def __init__(self, 
                 op_code, 
                 hw_type,
                 hw_len,
                 hop_count,
                 transaction_id,
                 elapsed_seconds,
                 flags,
                 client_ip,
                 your_ip,
                 server_ip,
                 gateway_ip,
                 client_hw_addr,
                 hw_addr_padding,
                 server_name,
                 boot_file_name,
                 magic_cookie, 
                 option_type):
        self._op_code = op_code
        self._hw_type = hw_type
        self._hw_len = hw_len
        self._hop_count = hop_count
        self._transaction_id = transaction_id
        self._elapsed_seconds = elapsed_seconds
        self._flags = flags
        self._client_ip = client_ip
        self._your_ip = your_ip
        self._server_ip = server_ip
        self._gateway_ip = gateway_ip
        self._client_hw_addr = client_hw_addr
        self._hw_addr_padding = hw_addr_padding
        self._server_name = server_name
        self._boot_file_name = boot_file_name
        self._magic_cookie = magic_cookie
        self._option_type = option_type

    def to_bytes(self):
        """
        Converte a estrutura DHCPFrame em bytes.
        """
        return (self._op_code.to_bytes(1, 'little')
                + self._hw_type.to_bytes(1, 'little')
                + self._hw_len.to_bytes(1, 'little')
                + self._hop_count.to_bytes(1, 'little')
                + self._transaction_id 
                + self._elapsed_seconds.to_bytes(2, 'little')
                + self._flags.to_bytes(2, 'little')
                + socket.inet_pton(socket.AF_INET, self._client_ip)
                + socket.inet_pton(socket.AF_INET, self._your_ip)
                + socket.inet_pton(socket.AF_INET, self._server_ip)
                + socket.inet_pton(socket.AF_INET, self._gateway_ip)
                + binascii.unhexlify(self._client_hw_addr)
                + binascii.unhexlify(self._hw_addr_padding)
                + binascii.unhexlify(self._server_name)
                + binascii.unhexlify(self._boot_file_name)
                + binascii.unhexlify(self._magic_cookie)
                + DHCPOptions.get_options_by_type(self._option_type)
                )

class EthernetFrame:
    def __init__(self, dst, src, eth_type):
        self._dst = dst
        self._src = src
        self._eth_type = eth_type

class IPv4Frame:
    def __init__(self, ver, header_len, tos, ident, flags, ttl, proto, checksum, src, dst, options):
        self._ver = ver
        self._header_len = header_len
        self._tos = tos
        self._ident = ident
        self._flags = flags
        self._ttl = ttl
        self._proto = proto
        self._checksum = checksum
        self._src = src
        self._dst = dst
        self._options = options

class DHCPOptions(Enum):
    OFFER = 'offer'
    ACK = 'ack'

    @staticmethod
    def get_options_by_type(option_type):
        """
        Retorna as opções de DHCP de acordo com o tipo de pacote (OFFER ou ACK).
        """
        if option_type == DHCPOptions.OFFER:
            return DHCPOptions.get_offer_options()
        elif option_type == DHCPOptions.ACK:
            return DHCPOptions.get_ack_options()
        return 

    @staticmethod
    def get_offer_options():
        """
        Retorna as opções para o pacote DHCP OFFER.
        """
        return (binascii.unhexlify(DHCPOptions.option_53_offer() + DHCPOptions.option_51() + DHCPOptions.option_1() + DHCPOptions.option_59())
                + DHCPOptions.option_3() + DHCPOptions.option_6() + DHCPOptions.option_54() + DHCPOptions.option_28() + DHCPOptions.option_255()
               )
    
    @staticmethod
    def get_ack_options():
        """
        Retorna as opções para o pacote DHCP ACK.
        """
        return (binascii.unhexlify(DHCPOptions.option_53_ack() + DHCPOptions.option_51() + DHCPOptions.option_1() + DHCPOptions.option_59())
                + DHCPOptions.option_3() + DHCPOptions.option_6() + DHCPOptions.option_54() + DHCPOptions.option_28() + DHCPOptions.option_255()
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
        return binascii.unhexlify('0304') + DHCPOptions.get_ip()
    
    @staticmethod
    def option_6():
        return binascii.unhexlify('0604') + DHCPOptions.get_ip()

    @staticmethod
    def option_54():
        return binascii.unhexlify('3604') + DHCPOptions.get_ip()

    @staticmethod
    def option_28():
        return binascii.unhexlify('1c04') + DHCPOptions.get_broadcast_ip()

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
        return socket.inet_pton(socket.AF_INET, '192.168.15.10')
