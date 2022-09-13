from threading import local
from manager.args import readArguments

import socket
import os
from formatter import format
from filter import filter

def main():
    args = readArguments()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    localMACS = filter.get_local_macs()

    while True:
        r_data, addr = s.recvfrom(args.packetSize)
        del addr
        eth = format.ethernet_head(r_data) 

        if eth[1] in localMACS:
            continue

        terminal_size_col = os.get_terminal_size()[0]

        print("\n")
        for _ in range(terminal_size_col):
            print("_", end="")

        print("Ethernet Frame:")
        print(f"Destination: {eth[0]}, Source: {eth[1]}, Protocol: {eth[2]}")

        if eth[2] == 8:
            ipv4 = format.ipv4_head(eth[3])

            print("\t - IPV4 Packet")
            print(f"\t\t - Version: {ipv4[1]}, Header Length: {ipv4[2]}, TTL: {ipv4[3]}")
            print(f"\t\t - Protocol: {ipv4[4]}, Source: {ipv4[5]}, Target: {ipv4[6]}")

            if ipv4[4] == 6:
                tcp = format.tcp_head(ipv4[7])

                print("\t - TCP Segment:")
                print(f"\t\t - Source Port: {tcp[0]}, Destination Port: {tcp[1]}")
                print(f"\t\t - Sequence: {tcp[2]}, Acknowledgment: {tcp[3]}")
                print("\t\t - Flags:")
                print(f"\t\t\t - URG: {tcp[4]}, ACK: {tcp[5]}, PSH: {tcp[6]}")
                print(f"\t\t\t - RST: {tcp[7]}, SYN: {tcp[8]}, FIN: {tcp[9]}")

                if len(tcp[10]) > 0:

                    if tcp[0] == 80 or tcp[1] == 80:
                        print("\t\t - HTTP Data:")
                        try:
                            http = format.decode_http(tcp[10])
                            http_info = str(http[10]).split("\n")

                            for line in http_info:
                                print(f"\t\t\t{str(line)}")
                        except:
                            print(format.multi_line_format("\t\t\t ", tcp[10]))
                    else:
                        print("\t\t - TCP Data:")
                        print(format.multi_line_format("\t\t\t ", tcp[10]))

            elif ipv4[4] == 1:
                icmp = format.icmp_head(ipv4[7])

                print("\t - ICMP Packet:")
                print(f"\t\t - Type: {icmp[0]}, Code: {icmp[1]}, Checksum: {icmp[2]}")
                print(f"\t\t - ICMP Data:")
                print(format.multi_line_format("\t\t\t ", icmp[3]))

            elif ipv4[4] == 17:
                udp = format.udp_head(ipv4[7])

                print("\t - UDP Segment:")
                print(f"\t\t - Source Port: {udp[0]}, Destination Port: {udp[1]}, Length: {udp[2]}")

            else:
                print("\t - Other IPv4 Data:")
                print(format.multi_line_format("\t\t", ipv4[7]))

        else:
            print("Ethernet Data:")
            print(format.multi_line_format("\t", eth[3]))


        for _ in range(terminal_size_col):
            print("_", end="")

if __name__ == '__main__':
    main()
