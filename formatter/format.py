import textwrap
import socket
import struct

def get_mac_addr(mac):
    """
    get the mac address from the raw data passed into the function
    :param mac: The raw mac address passed in
    :return: a readable mac address
    """

    byte_str = map('{:02x}'.format, mac)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def multi_line_format(prefix, string, size=80):
    """
    Fromat multiple lines of bytes
    """
    size -= len(prefix)

    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)

        if size%2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ethernet_head(r_data):
    """
    Unpack the ethernet head of the data
    """

    dest, src, prototype = struct.unpack('! 6s 6s H', r_data[:14])

    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = r_data[14:]

    return dest_mac, src_mac, proto, data

def decode_http(r_data):
    """
    if in http format then decode the utf-8 format
    """

    try:
        data = r_data.decode('utf-8')
    except:
        data = r_data

    return data

def icmp_head(r_data):
    """
    Unpack the icmp head 
    """

    packet_type, code, checksum = struct.unpack('! B B H', r_data[:4])
    data = r_data[4:]

    return packet_type, code, checksum, data

def get_ip(addr):
    """
    format the ip address into readable data
    """

    return '.'.join(map(str, addr))

def ipv4_head(r_data):
    """
    Unpack the ipv4 head
    """

    version_header_length = r_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', r_data[:20])
    
    src = get_ip(src)
    target = get_ip(target)
    data = r_data[header_length:]

    return version_header_length, version, header_length, ttl, proto, src, target, data

def tcp_head(r_data):
    """
    Extract the tcp head from the data
    """

    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', r_data[:14])

    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    data = r_data[offset:]

    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def udp_head(r_data):
    """
    Extract the udp head of the packet
    """

    src_port, dest_port, size = struct.unpack('! H H 2x H', r_data[:8])
    data = r_data[:8]

    return src_port, dest_port, size, data
