import socket
import argparse
import logging
from packet_parser import PacketParser
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from filters import *

logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', level=logging.INFO)


def main(output_file, dest_port, dest_ip, protocol):
    dest_ip_to_filter = socket.inet_aton(dest_ip) if dest_ip != "*" else "*"
    dest_port_to_filter = int(dest_port) if dest_port != "*" else "*"
    protocol_to_filter = int(protocol) if protocol != "*" else "*"

    filters_to_apply = [
        lambda packet, ethertype: filter_dest_ip(packet, ethertype, dest_ip_to_filter),
        lambda packet, ethertype: filter_dest_port(packet, ethertype, dest_port_to_filter),
        lambda packet, ethertype: filter_protocol(packet, ethertype, protocol_to_filter)
    ]
    print(f"Start capturing. Press Ctrl+C to stop.")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    parser = PacketParser(output_file)
    try:
        while True:
            send_test_packet()
            packet = s.recvfrom(2048)
            if filter_packet(packet[0], filters_to_apply):
                parser.parse_packet(packet[0])
                parser.write_to_pcap(packet[0])

    except KeyboardInterrupt:
        print(" Capture stopped.")
    finally:
        s.close()
        print("Closing the program.")


def send_test_packet():
    packet = (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.1", dst="192.168.1.2") /
              UDP(dport=1234))
    sendp(packet, iface="eth0", verbose=0)


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Capture and filter network traffic.")
    argparser.add_argument("--output_file", default="output.pcap", help="Output file name (default: output.pcap)")
    argparser.add_argument("--dest-port", default="*",
                           help="Destination port to filter (default: *), use * to disable filtering")
    argparser.add_argument("--dest-ip", default="*",
                           help="Destination IP address to filter, example: 192.168.1.1 (default: *), use * to disable filtering")
    argparser.add_argument("--protocol", default="*",
                           help="Protocol to filter, example: TCP (default: *), use * to disable filtering")

    args = argparser.parse_args()
    if args.dest_ip != "*" and not is_valid_ip(args.dest_ip):
        print("Invalid destination IP.")
        exit(1)

    if args.dest_port != "*" and not args.dest_port.isdigit():
        print("Invalid destination port.")
        exit(1)

    if args.protocol != "*" and args.protocol.lower() not in ["tcp", "udp"]:
        print("Invalid protocol.")
        exit(1)
    else:
        if args.protocol.lower() == "tcp":
            args.protocol = 6
        elif args.protocol.lower() == "udp":
            args.protocol = 17

    main(args.output_file, args.dest_port, args.dest_ip, args.protocol)
