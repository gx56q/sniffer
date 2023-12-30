import binascii
import logging
import socket
import struct
import time


class PacketParser:
    def __init__(self, output_file, validate_checksum=False):
        self.pcap_global_header_written = False
        self.output_file = output_file
        self.validate_checksum = validate_checksum
        self.pcap_file = open(output_file, 'wb')

        logging.basicConfig(filename="packet_log.txt", level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def __del__(self):
        self.pcap_file.close()

    @staticmethod
    def parse_ethernet_frame(packet):
        ethernet_header = packet[:14]
        eth_header = struct.unpack("!6s6sH", ethernet_header)
        dest_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
        src_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
        ethertype = eth_header[2]

        payload = packet[14:]
        return dest_mac, src_mac, ethertype, payload

    @staticmethod
    def parse_ip_header(payload):
        ip_header = struct.unpack("!BBHHHBBH4s4s", payload[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        checksum = ip_header[7]
        src_ip = ip_header[8]
        dest_ip = ip_header[9]

        return version, header_length, ttl, protocol, checksum, src_ip, dest_ip

    @staticmethod
    def parse_tcp_header(payload, header_length):
        tcp_header = struct.unpack("!HHIIBBHHH", payload[header_length:header_length + 20])
        src_port, dest_port, seq_num, ack_num, offset_flags, window_size, checksum, urgent_pointer = tcp_header

        offset = (offset_flags >> 4) * 4
        tcp_payload = payload[header_length + offset:]

        return src_port, dest_port, seq_num, ack_num, offset_flags, window_size, checksum, urgent_pointer, tcp_payload

    @staticmethod
    def parse_udp_header(payload, header_length):
        udp_header = struct.unpack("!HHHH", payload[header_length:header_length + 8])
        src_port, dest_port, length, checksum = udp_header
        udp_payload = payload[header_length + 8:]

        return src_port, dest_port, length, checksum, udp_payload

    def validate_tcp_checksum(self, tcp_header_info, src_ip, dest_ip, payload, header_length):
        pseudo_header = struct.pack('!IIIBBH',
                                    src_ip,
                                    dest_ip,
                                    0,
                                    6,
                                    len(payload) - header_length,
                                    0)
        pseudo_packet = pseudo_header + payload[header_length:]
        calculated_checksum = self.calculate_checksum(pseudo_packet)
        received_checksum = tcp_header_info[6]
        return calculated_checksum == received_checksum

    def validate_udp_checksum(self, received_checksum, src_ip, dest_ip, payload, header_length):
        pseudo_header = struct.pack('!IIIBBH',
                                    src_ip,
                                    dest_ip,
                                    0,
                                    17,
                                    len(payload) - header_length,
                                    0)
        pseudo_packet = pseudo_header + payload[header_length:]
        calculated_checksum = self.calculate_checksum(pseudo_packet)
        return calculated_checksum == received_checksum

    def validate_ip_checksum(self, received_checksum, src_ip, dest_ip, payload, header_length):
        pseudo_header = struct.pack('!II',
                                    src_ip,
                                    dest_ip)
        pseudo_packet = pseudo_header + payload[:header_length]
        calculated_checksum = self.calculate_checksum(pseudo_packet)
        return calculated_checksum == received_checksum

    @staticmethod
    def calculate_checksum(data):
        checksum = 0
        if len(data) % 2 != 0:
            data += b'\x00'
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            checksum += w
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        return checksum

    def parse_packet(self, packet):
        dest_mac, src_mac, ethertype, payload = self.parse_ethernet_frame(packet)
        result_str = f"Ethernet Frame\n" \
                     f"Destination MAC: {dest_mac}\n" \
                     f"Source MAC: {src_mac}\n" \
                     f"EtherType: {ethertype}\n" \
                     f"Payload: {binascii.hexlify(payload).decode('utf-8')}"

        if ethertype == 0x0800:  # IPv4
            version, header_length, ttl, protocol, checksum, src_ip, dest_ip = self.parse_ip_header(payload)
            result_str += f"\nIP Header\n" \
                          f"Version: {version}\n" \
                          f"Header Length: {header_length}\n" \
                          f"TTL: {ttl}\n" \
                          f"Protocol: {protocol}\n" \
                          f"Source IP: {socket.inet_ntoa(src_ip)}\n" \
                          f"Destination IP: {socket.inet_ntoa(dest_ip)}"
            if self.validate_checksum:
                is_valid = self.validate_ip_checksum(checksum, src_ip, dest_ip,
                                                     payload, header_length)
                result_str += f"\nIP Checksum Validation: {is_valid}"

            if protocol == 6:  # TCP
                tcp_header_info = self.parse_tcp_header(payload, header_length)
                result_str += f"\nTCP Header\n" \
                              f"Source Port: {tcp_header_info[0]}\n" \
                              f"Destination Port: {tcp_header_info[1]}\n" \
                              f"Sequence Number: {tcp_header_info[2]}\n" \
                              f"Acknowledgment Number: {tcp_header_info[3]}\n" \
                              f"Offset: {tcp_header_info[4] >> 4} (bytes)\n" \
                              f"Flags: {tcp_header_info[4] & 0xF}\n" \
                              f"Window Size: {tcp_header_info[5]}\n" \
                              f"Checksum: {tcp_header_info[6]}\n" \
                              f"Urgent Pointer: {tcp_header_info[7]}\n" \
                              f"TCP Payload: {binascii.hexlify(tcp_header_info[8]).decode('utf-8')}"

                if self.validate_checksum:
                    is_valid = self.validate_tcp_checksum(tcp_header_info,
                                                          src_ip,
                                                          dest_ip,
                                                          payload,
                                                          header_length)
                    result_str += f"\nTCP Checksum Validation: {is_valid}"

            elif protocol == 17:  # UDP
                udp_header_info = self.parse_udp_header(payload, header_length)
                result_str += f"\nUDP Header\n" \
                              f"Source Port: {udp_header_info[0]}\n" \
                              f"Destination Port: {udp_header_info[1]}\n" \
                              f"Length: {udp_header_info[2]}\n" \
                              f"Checksum: {udp_header_info[3]}\n" \
                              f"UDP Payload: {binascii.hexlify(udp_header_info[4]).decode('utf-8')}"

                if self.validate_checksum:
                    is_valid = self.validate_udp_checksum(udp_header_info[3],
                                                          src_ip,
                                                          dest_ip,
                                                          payload,
                                                          header_length)
                    result_str += f"\nUDP Checksum Validation: {is_valid}"

        logging.info(result_str)
        return result_str

    def write_to_pcap(self, packet):
        ts_sec, ts_usec = map(int, divmod(time.time(), 1e6))
        incl_len = len(packet)
        orig_len = len(packet)

        if not self.pcap_global_header_written:
            self.pcap_file.write(struct.pack('=IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 1600, 1))
            self.pcap_global_header_written = True

        pcap_header = struct.pack('=IIII', ts_sec, ts_usec, incl_len, orig_len)
        self.pcap_file.write(pcap_header + packet)
