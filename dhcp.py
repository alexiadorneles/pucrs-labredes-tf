import binascii
import socket
import struct

class DHCPHandler(object):
    def __init__(self, data_packet, data_length):
        self._raw_data = data_packet  # Pacote de dados brutos
        self._data_length = data_length  # Comprimento dos dados
        self._client_ip = ''  # Endereço IP do cliente
        self._client_hw_addr = ''  # Endereço de hardware do cliente
        self._req_list_opt = ''  # Opção de lista de solicitações (option 55)
        self._msg_type_opt = ''  # Tipo de mensagem DHCP (option 53)
        self._hostname_opt = ''  # Nome do host (option 12)
        self._req_ip_opt = ''  # IP solicitado (option 50)
        self._server_id_opt = ''  # ID do servidor (option 54)
        self._trans_id = ''  # ID da transação
    
    def extract_data(self):
        """
        Extrai e analisa dados do payload DHCP.
        - client_ip: Endereço IP do cliente [12:16]
        - client_hw_addr: Endereço de hardware do cliente [28:34]
        """
        tmp = struct.unpack('!4s', self._raw_data[12:16])
        self._client_ip = socket.inet_ntoa(tmp[0])  # Converte o endereço IP do cliente de binário para string
        self._client_hw_addr = binascii.hexlify(self._raw_data[28:34]).decode()  # Converte o endereço de hardware para hexadecimal

    def extract_options(self):
        """
        Analisa e extrai as opções DHCP do payload.
        - Magic Cookie + Opções DHCP + FF (fim das opções)
        - Formato das opções DHCP: código (1 byte) + comprimento (1 byte) + valor
        - Formato de Pad e End option: código (1 byte)
        """
        is_found = False
        raw_hex_data = binascii.hexlify(self._raw_data).decode()  # Converte os dados brutos para hexadecimal
        self._trans_id = bytes.fromhex(raw_hex_data[8:16])  # Extrai o ID da transação
        cookie_index = raw_hex_data.find(DHCPProtocol.magic_cookie)  # Encontra o índice do Magic Cookie
        if -1 == cookie_index:
            return

        cookie_index += len(DHCPProtocol.magic_cookie)
        total_hex_length = self._data_length * 2  # Comprimento total em hexadecimal
        while True:
            opt_code = int(raw_hex_data[cookie_index:cookie_index+2], 16)  # Código da opção
            if DHCPProtocol.opt_pad == opt_code:
                cookie_index += 2
                continue
            if DHCPProtocol.opt_end == opt_code:
                return
            opt_length = int(raw_hex_data[cookie_index+2:cookie_index+4], 16)  # Comprimento da opção
            opt_value = raw_hex_data[cookie_index+4:cookie_index+4+opt_length*2]  # Valor da opção

            # Define as opções DHCP
            if DHCPProtocol.opt_req_list == opt_code:
                self._req_list_opt = opt_value
            elif DHCPProtocol.opt_msg_type == opt_code:
                self._msg_type_opt = DHCPProtocol.get_message_type(int(opt_value))
            elif DHCPProtocol.opt_hostname == opt_code:
                self._hostname_opt = bytes.fromhex(opt_value).decode()
            elif DHCPProtocol.opt_req_ip == opt_code:
                ip_bytes = bytes.fromhex(opt_value)
                self._req_ip_opt = socket.inet_ntoa(ip_bytes)
            elif DHCPProtocol.opt_server_id == opt_code:
                server_id_bytes = bytes.fromhex(opt_value)
                self._server_id_opt = socket.inet_ntoa(server_id_bytes)

            cookie_index = cookie_index + 4 + opt_length * 2

            if cookie_index + 4 > total_hex_length:
                break

    @property
    def client_ip(self):
        return self._client_ip

    @property
    def client_hw_addr(self):
        return self._client_hw_addr

    @property
    def req_list_opt(self):
        return self._req_list_opt

    @property
    def msg_type_opt(self):
        return self._msg_type_opt

    @property
    def hostname_opt(self):
        return self._hostname_opt

    @property
    def req_ip_opt(self):
        return self._req_ip_opt

    @property
    def server_id_opt(self):
        return self._server_id_opt
    
    @property
    def trans_id(self):
        return self._trans_id

class DHCPProtocol(object):
    server_port = 67
    client_port = 68

    # DHCP options
    magic_cookie = '63825363'
    opt_pad = 0
    opt_hostname = 12
    opt_req_ip = 50
    opt_msg_type = 53
    opt_server_id = 54
    opt_req_list = 55
    opt_end = 255

    @staticmethod
    def get_message_type(value):
        msg_type = {
            1: 'DHCPDISCOVER',
            2: 'DHCPOFFER',
            3: 'DHCPREQUEST',
            4: 'DHCPDECLINE',
            5: 'DHCPACK',
            6: 'DHCPNAK',
            7: 'DHCPRELEASE',
            8: 'DHCPINFORM'
        }
        return msg_type.get(value, 'None')
