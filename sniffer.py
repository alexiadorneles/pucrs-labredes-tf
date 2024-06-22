from itertools import count
import opcode
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
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    step = 'DHCPDISCOVER'

    should_print = False

    ip_assigned = '172.26.144.1'
    #s2.bind(('0.0.0.0', 68))
    print("Waiting for dhcp discover from client...")
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        #Ipv4 Protocol(Internet Layer)
        if eth[2] == '0x800':
            ipv4 = ipv4_head(eth[3])
            should_print = should_print_packages(ip_assigned, ipv4[4])
            print_ethernet(should_print, eth)
            print_ipv4(should_print, ipv4)
            
            #TCP
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])
                print_tcp(should_print, tcp)

                if tcp[0] == 53 or tcp[1] == 53:
                    dns = dns_head(tcp[10])
                    print_dns(should_print, dns)
                else:
                    if len(tcp[10]) > 0 and should_print:
                        # HTTP
                        if tcp[0] == 80 or tcp[1] == 80:
                            print('\t\t -' + 'HTTP Data:')
                            try:
                                http = http(tcp[10])
                                http_info = str(http[10]).split('\n')
                                for line in http_info:
                                    print('\t\t\t' + str(line))
                            except:
                                print(format_multi_line('\t\t\t', tcp[10]))
                        else:
                            print('\t\t -' + 'TCP Data:')
                            print(format_multi_line('\t\t\t', tcp[10]))
            #ICMP
            elif ipv4[3] == 1:
                icmp = icmp_head(ipv4[6])
                print_icmp(should_print, icmp)

            #HERE
            #UDP            
            if ipv4[3] == 17:
                udp = udp_head(ipv4[6])
                print_udp(should_print,udp)
                #DNS
                #Client source 68 destination 67
                #SRV source 67 destination 68
                if udp[0] == 68 or udp[1] == 67:
                    dhcp_package = DHCP(udp[4], udp[2] - 8)
                    dhcp_package.parse_options()
                    dhcp_package.parse_payload()
                    if dhcp_package._option_53 == 'DHCPDISCOVER' and step == 'DHCPDISCOVER':
                        print('Received Discover, sending offer...')
                        payload = DHCPPayload(2,1,6,0, dhcp_package._transaction_id, 0x0000, 0x0000,
                            '0.0.0.0', ip_assigned, '0.0.0.0', '0.0.0.0', dhcp_package._chaddr, '00000000000000000000',
                            '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                            '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                            DHCP_Protocol.magic_cookie, Options.OFFER)
                        s2.sendto(payload.get_bytes(), ('255.255.255.255', 68))
                        step = 'DHCPREQUEST'
                    elif dhcp_package._option_53 == 'DHCPREQUEST' and step == 'DHCPREQUEST':
                        print('Received Request, sending ack...')
                        payload = DHCPPayload(2,1,6,0, dhcp_package._transaction_id, 0x0000, 0x0000,
                            '0.0.0.0', ip_assigned, '0.0.0.0', '0.0.0.0', dhcp_package._chaddr, '00000000000000000000',
                            '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                            '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
                            DHCP_Protocol.magic_cookie, Options.ACK)
                        s2.sendto(payload.get_bytes(), ('255.255.255.255', 68))

                elif (udp[0] == 53 or udp[1] == 53) and should_print:
                    dns = dns_head(udp[4])
                    print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns[0], dns[1], dns[2], dns[3], dns[4], dns[5]))
                #else:
                #   print(format_multi_line('\t\t\t', udp[4]))




        # #ARP
        elif eth[2] == '0x806':
            arp = arp_head(eth[3])
            print_arp(should_print, arp)
        #IPV6 Protocol(Internet Layer)
        if eth[2] == '0x86dd' and should_print:
            ipv6 = ipv6Header(eth[3])
            print( '\t - ' + 'IPv6 Packet:')
            print('\t\t - ' + 'Version: {}, Payload Length: {}, Next Header: {},'.format(ipv6[0], ipv6[1], ipv6[2]))
            print('\t\t - ' + 'Hop Limit: {}, Source: {}, Target: {}'.format(ipv6[3], ipv6[4], ipv6[5]))
            print('\t\t - ' + 'Traffic class: {}, Flow Label: {}'.format(ipv6[6], ipv6[7]))

            #ICMPv6 
            if ipv6[2] == 58 and should_print:
                icmpv6 = icmpv6Header(ipv6[8])
                print('\t - ' + 'ICMP Packet:')
                print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmpv6[0], icmpv6[1], icmpv6[2]))	
        
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = hex(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data

def get_ip(addr):
    return '.'.join(map(str, addr))

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data
    
def get_mac_addr(bytes_addr) :
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def icmp_head(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, hex(checksum), data[16:]

def udp_head(raw_data):
    src_port, dest_port, size, checksum = struct.unpack('! H H H H', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, size, hex(checksum), data

def dns_head(raw_data):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('! H H H H H H', raw_data[:12])
    return hex(id), hex(flags), qdcount, ancount, nscount, arcount

def arp_head(raw_data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, source_mac, source_ip, dest_mac, dest_ip = struct.unpack("! H H B B H 6s 4s 6s 4s", raw_data[:28])
    return hardware_type, hex(protocol_type), hardware_size, protocol_size, opcode, source_mac, source_ip, dest_mac, dest_ip

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def ipv6Header(data):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(
        ">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 8323072
    flow_label = int(ipv6_first_word) & 2097151

    data = data[40:]

    return  version, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit, ipv6_src_ip, ipv6_dst_ip, traffic_class, hex(flow_label), data


def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_checksum = struct.unpack(
        ">BBH", data[:4])

    data = data[4:]
    return ipv6_icmp_type, ipv6_icmp_code, hex(ipv6_icmp_checksum), data

def get_total(counters):
    return counters[0] + counters[1] + counters[2]

def format_to_percentage(value):
    return value * 100

def should_print_packages(incoming_ip, client_ip):
    return incoming_ip == client_ip

def print_ethernet(should_print, eth):
    if should_print:
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))


def print_ipv4(should_print, ipv4):
    if should_print:
        print( '\t - ' + 'IPv4 Packet:')
        print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4[0], ipv4[1], ipv4[2]))
        print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))	

def print_tcp(should_print, tcp):
    if should_print:
        print('\t - ' + 'TCP Segment:')
        print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
        print('\t\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
        print('\t\t - ' + 'Flags:')
        print('\t\t\t - ' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
        print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))

def print_dns(should_print, dns):
    if should_print:
        print('ID: {} Flags: {} QDCOUNT: {} ANCOUNT: {} NSCOUNT: {} ARCOUNT: {}'.format(dns[0], dns[1], dns[2], dns[3], dns[4], dns[5]))

def print_icmp(should_print, icmp):
    if should_print:
        print('\t - ' + 'ICMP Packet:')
        print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp[0], icmp[1], icmp[2]))				
        print('\t\t -' + ' ICMP Data:')
        print(format_multi_line('\t\t\t', icmp[3]))

def print_udp(should_print, udp):
    if should_print:
        print('\t -' + ' UDP Segment:')
        print('\t\t -' + ' Source Port: {}, Destination Port: {}, Length: {}, CheckSum: {}'.format(
                    udp[0], udp[1], udp[2], udp[3]))

def print_arp(should_print, arp):
    if should_print:
        print( '\t - ' + 'ARP Packet:')
        print('\t\t - ' + 'Hardware type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
        print('\t\t - ' + 'Hardware Size: {}, Protocol Size: {}, Opcode: {}'.format(arp[2], arp[3], arp[4]))
        print('\t\t - ' + 'Source MAC: {}, Source Ip: {}'.format(get_mac_addr(arp[5]), get_ip(arp[6])))
        print('\t\t - ' + 'Dest MAC: {}, Dest Ip: {}'.format(get_mac_addr(arp[7]), get_ip(arp[8])))

main()