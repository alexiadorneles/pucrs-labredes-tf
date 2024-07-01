import binascii
import socket
import struct
from struct import *
import sys
import textwrap
from dhcp import *
from payloads import *
import pickle

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # s2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    dhcp_state = 'DHCPDISCOVER'

    print_status = False
    assigned_ip = '172.26.144.1'
    print("Waiting for DHCP discover from client...")

    while True:
        raw_pkt, addr = s.recvfrom(65535)
        eth_header = parse_ethernet_header(raw_pkt)

        if eth_header[2] == '0x800':  # IPv4
            ipv4_header = parse_ipv4_header(eth_header[3])
            print_status = should_display_packets(assigned_ip, ipv4_header[4])
            display_ethernet(print_status, eth_header)
            display_ipv4(print_status, ipv4_header)

            if ipv4_header[3] == 6:  # TCP
                tcp_header = parse_tcp_header(ipv4_header[6])
                if tcp_header[0] == 53 or tcp_header[1] == 53: # DNS
                    dns_header = parse_dns_header(tcp_header[10])
                    display_dns(print_status, dns_header)

            elif ipv4_header[3] == 17:  # UDP
                udp_header = parse_udp_header(ipv4_header[6])
                display_udp(print_status, udp_header)

                if udp_header[0] == 68 or udp_header[1] == 67:  # DHCP
                    dhcp_packet = DHCPHandler(udp_header[4], udp_header[2] - 8)
                    dhcp_packet.parse_options()
                    dhcp_packet.parse_payload()
                    if dhcp_packet.option_53 == 'DHCPDISCOVER' and dhcp_state == 'DHCPDISCOVER':
                        print('Received Discover, sending offer...')
                        dhcp_offer_payload = DHCPFrame(2, 1, 6, 0, dhcp_packet.transaction_id, 0x0000, 0x0000,
                                                         '0.0.0.0', assigned_ip, '0.0.0.0', '0.0.0.0', dhcp_packet.chaddr, '00000000000000000000',
                                                         '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                         '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                         DHCPProtocol.magic_cookie, DHCPOptions.OFFER)
                        send_dhcp_msg(s, dhcp_offer_payload)
                        # s2.sendto(dhcp_offer_payload.get_bytes(), ('255.255.255.255', 68))
                        dhcp_state = 'DHCPREQUEST'
                    elif dhcp_packet.option_53 == 'DHCPREQUEST' and dhcp_state == 'DHCPREQUEST':
                        print('Received Request, sending ack...')
                        dhcp_ack_payload = DHCPFrame(2, 1, 6, 0, dhcp_packet.transaction_id, 0x0000, 0x0000,
                                                       '0.0.0.0', assigned_ip, '0.0.0.0', '0.0.0.0', dhcp_packet.chaddr, '00000000000000000000',
                                                       '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                       '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                       DHCPProtocol.magic_cookie, DHCPOptions.ACK)
                        send_dhcp_msg(s, dhcp_ack_payload)
                        # s2.sendto(dhcp_ack_payload.get_bytes(), ('255.255.255.255', 68))

                elif (udp_header[0] == 53 or udp_header[1] == 53) and print_status:  # DNS
                    dns_header = parse_dns_header(udp_header[4])
                    print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns_header[0], dns_header[1], dns_header[2], dns_header[3], dns_header[4], dns_header[5]))

        elif eth_header[2] == '0x806':  # ARP
            arp_header = parse_arp_header(eth_header[3])
            display_arp(print_status, arp_header)

def parse_ethernet_header(raw_data):
    """
    Analisa o cabeçalho Ethernet.
    """
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = format_mac_addr(dest)
    src_mac = format_mac_addr(src)
    proto = hex(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def parse_ipv4_header(raw_data):
    """
    Analisa o cabeçalho IPv4.
    """
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = format_ip(src)
    target = format_ip(target)
    return version, header_length, ttl, proto, src, target, data

def format_ip(addr):
    """
    Converte um endereço binário para string.
    """
    return '.'.join(map(str, addr))

def parse_tcp_header(raw_data):
    """
    Analisa o cabeçalho TCP.
    """
    (src_port, dest_port, seq, ack, offset_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_flags >> 12) * 4
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_rst = (offset_flags & 4) >> 2
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def format_mac_addr(bytes_addr):
    """
    Formata o endereço MAC.
    """
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def parse_udp_header(raw_data):
    """
    Analisa o cabeçalho UDP.
    """
    src_port, dest_port, size, checksum = struct.unpack('! H H H H', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, size, hex(checksum), data

def parse_dns_header(raw_data):
    """
    Analisa o cabeçalho DNS.
    """
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('! H H H H H H', raw_data[:12])
    return hex(id), hex(flags), qdcount, ancount, nscount, arcount

def parse_arp_header(raw_data):
    """
    Analisa o cabeçalho ARP.
    """
    hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dest_mac, dest_ip = struct.unpack("! H H B B H 6s 4s 6s 4s", raw_data[:28])
    return hw_type, hex(proto_type), hw_size, proto_size, opcode, src_mac, src_ip, dest_mac, dest_ip

def format_multiline_output(prefix, string, size=80):
    """
    Formata a saída de múltiplas linhas.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def total_packets_count(counters):
    """
    Retorna o total de pacotes contados.
    """
    return counters[0] + counters[1] + counters[2]

def convert_to_percentage(value):
    """
    Converte um valor para porcentagem.
    """
    return value * 100

def should_display_packets(incoming_ip, client_ip):
    """
    Verifica se os pacotes devem ser exibidos com base no IP.
    """
    return incoming_ip == client_ip

def display_ethernet(should_display, eth):
    """
    Exibe informações do cabeçalho Ethernet.
    """
    if should_display:
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))

def display_ipv4(should_display, ipv4):
    """
    Exibe informações do cabeçalho IPv4.
    """
    if should_display:
        print('\t - ' + 'IPv4 Packet:')
        print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4[0], ipv4[1], ipv4[2]))
        print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))

def display_dns(should_display, dns):
    """
    Exibe informações do cabeçalho DNS.
    """
    if should_display:
        print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns[0], dns[1], dns[2], dns[3], dns[4], dns[5]))

def display_udp(should_display, udp):
    """
    Exibe informações do cabeçalho UDP.
    """
    if should_display:
        print('\t -' + ' UDP Segment:')
        print('\t\t -' + ' Source Port: {}, Destination Port: {}, Length: {}, CheckSum: {}'.format(udp[0], udp[1], udp[2], udp[3]))

def display_arp(should_display, arp):
    """
    Exibe informações do cabeçalho ARP.
    """
    if should_display:
        print('\t - ' + 'ARP Packet:')
        print('\t\t - ' + 'Hardware type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
        print('\t\t - ' + 'Hardware Size: {}, Protocol Size: {}, Opcode: {}'.format(arp[2], arp[3], arp[4]))
        print('\t\t - ' + 'Source MAC: {}, Source Ip: {}'.format(format_mac_addr(arp[5]), format_ip(arp[6])))
        print('\t\t - ' + 'Dest MAC: {}, Dest Ip: {}'.format(format_mac_addr(arp[7]), format_ip(arp[8])))

def send_dhcp_msg(raw_socket, dhcp_frame):
    # Ethernet frame
    eth_dst = binascii.unhexlify('ffffffffffff')  # Broadcast
    eth_src = binascii.unhexlify('001122334455')  # Replace with MAC address
    eth_type = struct.pack('!H', 0x0800)  # IPv4

    # IP header
    ip_ihl_ver = struct.pack('!B', 0x45)
    ip_tos = struct.pack('!B', 0x00)
    ip_tot_len = struct.pack('!H', 0x0138)
    ip_id = struct.pack('!H', 0x0000)
    ip_frag_off = struct.pack('!H', 0x0000)
    ip_ttl = struct.pack('!B', 0x80)
    ip_proto = struct.pack('!B', 0x11)  # UDP
    ip_checksum = struct.pack('!H', 0x0000)
    ip_src = socket.inet_aton('0.0.0.0')
    ip_dst = socket.inet_aton('255.255.255.255')

    ip_header = ip_ihl_ver + ip_tos + ip_tot_len + ip_id + ip_frag_off + ip_ttl + ip_proto + ip_checksum + ip_src + ip_dst

    # UDP header
    udp_src = struct.pack('!H', 68)  # Source port
    udp_dst = struct.pack('!H', 67)  # Destination port
    udp_len = struct.pack('!H', 0x0124)
    udp_checksum = struct.pack('!H', 0x0000)

    udp_header = udp_src + udp_dst + udp_len + udp_checksum
    dhcp_packet = dhcp_frame.to_bytes()
    
    packet = eth_dst + eth_src + eth_type + ip_header + udp_header + dhcp_packet
  
    raw_socket.send(packet)



main()
