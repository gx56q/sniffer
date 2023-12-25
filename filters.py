import struct


def filter_packet(packet, filters):
    ethertype = struct.unpack("!H", packet[12:14])[0]
    for filter_func in filters:
        if not filter_func(packet, ethertype):
            return False
    return True


def filter_protocol(packet, ethertype, protocol_to_filter="*"):
    if protocol_to_filter == "*":
        return True
    if ethertype == 0x0800:  # IPv4
        return packet[23] == protocol_to_filter
    return True


def filter_src_ip(packet, ethertype, src_ip_to_filter="*"):
    if src_ip_to_filter == "*":
        return True
    if ethertype == 0x0800:  # IPv4
        return packet[26:30] == src_ip_to_filter
    return True


def filter_dest_ip(packet, ethertype, dest_ip_to_filter="*"):
    if dest_ip_to_filter == "*":
        return True
    if ethertype == 0x0800:  # IPv4
        return packet[30:34] == dest_ip_to_filter
    return True


def filter_src_port(packet, ethertype, src_port_to_filter="*"):
    if src_port_to_filter == "*":
        return True
    if ethertype == 0x0800:  # IPv4
        return struct.unpack("!H", packet[34:36])[0] == src_port_to_filter
    return True


def filter_dest_port(packet, ethertype, dest_port_to_filter="*"):
    if dest_port_to_filter == "*":
        return True
    if ethertype == 0x0800:  # IPv4
        return struct.unpack("!H", packet[36:38])[0] == dest_port_to_filter
    return True
