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
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
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
                display_tcp(print_status, tcp_header)

                if tcp_header[0] == 53 or tcp_header[1] == 53:
                    dns_header = parse_dns_header(tcp_header[10])
                    display_dns(print_status, dns_header)
                else:
                    if len(tcp_header[10]) > 0 and print_status:
                        if tcp_header[0] == 80 or tcp_header[1] == 80:  # HTTP
                            print('\t\t -' + 'HTTP Data:')
                            try:
                                http_payload = parse_http_payload(tcp_header[10])
                                http_info = str(http_payload[10]).split('\n')
                                for line in http_info:
                                    print('\t\t\t' + str(line))
                            except:
                                print(format_multiline_output('\t\t\t', tcp_header[10]))
                        else:
                            print('\t\t -' + 'TCP Data:')
                            print(format_multiline_output('\t\t\t', tcp_header[10]))
            elif ipv4_header[3] == 1:  # ICMP
                icmp_header = parse_icmp_header(ipv4_header[6])
                display_icmp(print_status, icmp_header)

            elif ipv4_header[3] == 17:  # UDP
                udp_header = parse_udp_header(ipv4_header[6])
                display_udp(print_status, udp_header)

                if udp_header[0] == 68 or udp_header[1] == 67:  # DHCP
                    dhcp_packet = DHCP(udp_header[4], udp_header[2] - 8)
                    dhcp_packet.parse_options()
                    dhcp_packet.parse_payload()
                    if dhcp_packet.option_53 == 'DHCPDISCOVER' and dhcp_state == 'DHCPDISCOVER':
                        print('Received Discover, sending offer...')
                        dhcp_offer_payload = DHCPPayload(2, 1, 6, 0, dhcp_packet.transaction_id, 0x0000, 0x0000,
                                                         '0.0.0.0', assigned_ip, '0.0.0.0', '0.0.0.0', dhcp_packet.chaddr, '00000000000000000000',
                                                         '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                         '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                         DHCP_Protocol.magic_cookie, Options.OFFER)
                        s2.sendto(dhcp_offer_payload.get_bytes(), ('255.255.255.255', 68))
                        dhcp_state = 'DHCPREQUEST'
                    elif dhcp_packet.option_53 == 'DHCPREQUEST' and dhcp_state == 'DHCPREQUEST':
                        print('Received Request, sending ack...')
                        dhcp_ack_payload = DHCPPayload(2, 1, 6, 0, dhcp_packet.transaction_id, 0x0000, 0x0000,
                                                       '0.0.0.0', assigned_ip, '0.0.0.0', '0.0.0.0', dhcp_packet.chaddr, '00000000000000000000',
                                                       '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                       '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                                                       DHCP_Protocol.magic_cookie, Options.ACK)
                        s2.sendto(dhcp_ack_payload.get_bytes(), ('255.255.255.255', 68))

                elif (udp_header[0] == 53 or udp_header[1] == 53) and print_status:  # DNS
                    dns_header = parse_dns_header(udp_header[4])
                    print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns_header[0], dns_header[1], dns_header[2], dns_header[3], dns_header[4], dns_header[5]))

        elif eth_header[2] == '0x806':  # ARP
            arp_header = parse_arp_header(eth_header[3])
            display_arp(print_status, arp_header)

        elif eth_header[2] == '0x86dd' and print_status:  # IPv6
            ipv6_header = parse_ipv6_header(eth_header[3])
            print('\t - ' + 'IPv6 Packet:')
            print('\t\t - ' + 'Version: {}, Payload Length: {}, Next Header: {},'.format(ipv6_header[0], ipv6_header[1], ipv6_header[2]))
            print('\t\t - ' + 'Hop Limit: {}, Source: {}, Target: {}'.format(ipv6_header[3], ipv6_header[4], ipv6_header[5]))
            print('\t\t - ' + 'Traffic class: {}, Flow Label: {}'.format(ipv6_header[6], ipv6_header[7]))

            if ipv6_header[2] == 58 and print_status:  # ICMPv6
                icmpv6_header = parse_icmpv6_header(ipv6_header[8])
                print('\t - ' + 'ICMPv6 Packet:')
                print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmpv6_header[0], icmpv6_header[1], icmpv6_header[2]))	

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

def parse_icmp_header(data):
    """
    Analisa o cabeçalho ICMP.
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, hex(checksum), data[16:]

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

def parse_ipv6_header(data):
    """
    Analisa o cabeçalho IPv6.
    """
    ipv6_first_word, ipv6_payload_len, ipv6_next_hdr, ipv6_hoplimit = struct.unpack(">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    version = ipv6_first_word >> 28
    traffic_class = (ipv6_first_word >> 20) & 0xFF
    flow_label = ipv6_first_word & 0xFFFFF

    data = data[40:]
    return version, ipv6_payload_len, ipv6_next_hdr, ipv6_hoplimit, ipv6_src_ip, ipv6_dst_ip, traffic_class, hex(flow_label), data

def parse_icmpv6_header(data):
    """
    Analisa o cabeçalho ICMPv6.
    """
    icmpv6_type, icmpv6_code, icmpv6_checksum = struct.unpack(">BBH", data[:4])
    data = data[4:]
    return icmpv6_type, icmpv6_code, hex(icmpv6_checksum), data

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

def display_tcp(should_display, tcp):
    """
    Exibe informações do cabeçalho TCP.
    """
    if should_display:
        print('\t - ' + 'TCP Segment:')
        print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
        print('\t\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
        print('\t\t - ' + 'Flags:')
        print('\t\t\t - ' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
        print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))

def display_dns(should_display, dns):
    """
    Exibe informações do cabeçalho DNS.
    """
    if should_display:
        print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns[0], dns[1], dns[2], dns[3], dns[4], dns[5]))

def display_icmp(should_display, icmp):
    """
    Exibe informações do cabeçalho ICMP.
    """
    if should_display:
        print('\t - ' + 'ICMP Packet:')
        print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp[0], icmp[1], icmp[2]))
        print('\t\t -' + ' ICMP Data:')
        print(format_multiline_output('\t\t\t', icmp[3]))

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

main()
