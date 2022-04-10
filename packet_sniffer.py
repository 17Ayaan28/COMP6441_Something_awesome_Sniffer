import socket
import struct
import textwrap

import proto

# Struct is a library that is extensively used when dealing with networks in python.
# It has functions to deal with packed bytes like ones in networks

def main():
    
    # Initialise socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Infinite loop waiting for packets
    while True:
        data, address = conn.recvfrom(65536)
        destination, source, protocol ,data = unpack_frame(data)
        print("\n Ethernet Frame: " )
        print('Destination: {}, Source: {}, Protocol: {}'.format(destination, source, protocol))

        if (protocol == 8):

            (version, h_length, time_to_l, prot, source, destination, data) = ipv4_packet(data)
            print("IPV4 Packet:")
            print("Version: {}, Header Length: {}, TTL: {}".format(version, h_length,time_to_l))
            print("Protocol: {}, Source: {}, Target: {}".format(prot, source,destination))

            if (proto == 1):
                (source_port, destination_port, s_no, ack, urg,ack,psh, rst, syn, fin) = tcp_segment(data)
                print("TCP Segment")
                print("Source Port: {}, Destination Port: {}".format(source_port, destination_port))
                print("Sequence: {}, Ack: {}".format(s_no,ack))
                print("flags: urg : {}, ack : {}, psh: {}, rst:{}, syn:{}, fin{}".format(urg,ack,psh,rst,syn,fin))

# Unpacks the data frame
# Read Packnet Sniffer section in report for best understanding
# The way the pack and unpack functions work with networks is a little ambigous in most sources I read and even in the documentation. 
# The formatted string below extracts 6 bytes for dest(s is a char array), 6 for src and then 2 bytes that is a short(H) for the length
# However, it does nothing to intial 8 bytes, this is due to how the datagram is packed
# '!' is used when dealing with packed bytes in networks. It converts to big endian or little endian depending on the system
# Different systems - For example, Intel x86 and AMD64 (x86-64) are little-endian; Motorola 68000 and PowerPC G5 are big-endian

def unpack_frame(data):
    destination_address, source_address, length = struct.unpack('! 6s 6s H', data[:14]) # gets first 14 bytes and extracts the following from it
    return get_address(destination_address), get_address(source_address), socket.htons(length), data[14:]

    # the rest of the data from 14 bytes onwards contains the IP layer with the the data and hence we return it. We don't know how big it is so we return
    # everything after 14 bytes

# The addresses need to be converted to human readable form
# It converts the bytes to hex and seperated every 2 by a ':'
def get_address(address):
    bytes_str = map('{:02X}'.format, address)
    h_addr =  ':'.join(bytes_str).upper()
    return h_addr

# Used to unpack IP address
# look at diagram in report to understand splitting
def ipv4_packet(data):
    first_byte = data[0] # first byte is version and header_length
    IP_version = first_byte >> 4 # shifts header_length out to get version
    header_length = (first_byte & 15) * 4 # gets header length using bitwise & , 15 is 1111
    time_to_live, protocol, source, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # x basically ignore the number of bytes, so we start from ttl, 
                                                                                        # protocol after ignoring 8 bytes(2) rows, we ignore checksum and then get source and dest
    return IP_version, header_length, time_to_live,protocol, get_IPaddress(source), get_IPaddress(dest), data[header_length:]

# converts bytes to string like 134.0.0.5
def get_IPaddress(addr):
    IP_address =  '.'.join(map(str,addr))
    return IP_address


def tcp_segment(data):
    # H - 2 bytes short
    # L - 4 bytes long
    # 2 bytes each for source and port, then full 32 bites for sequence and acknowledgement and then 2 bytes for all the flags
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    h_length = (offset_reserved_flags >> 12)*4  # get header_length
    urg = (offset_reserved_flags & 32) >> 5     # get flags
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence ,acknowledgement, urg, ack, psh,  rst, syn, fin, data[h_length:] # get all data after header length

