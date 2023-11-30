import pcapy
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter


def packet_callback(packet):
    eth_frame = Ether(packet)
    print("Packet captured:")
    print(eth_frame.summary())
    if IP in eth_frame:
        print(f"Source IP: {eth_frame[IP].src}")
        print(f"Destination IP: {eth_frame[IP].dst}")
        if TCP in eth_frame:
            print(f"Source Port: {eth_frame[TCP].sport}")
            print(f"Destination Port: {eth_frame[TCP].dport}")
        elif UDP in eth_frame:
            print(f"Source Port: {eth_frame[UDP].sport}")
            print(f"Destination Port: {eth_frame[UDP].dport}")
    elif IPv6 in eth_frame:
        print(f"Source IPv6: {eth_frame[IPv6].src}")
        print(f"Destination IPv6: {eth_frame[IPv6].dst}")

    print("=" * 60)


def main(output_file):
    cap = pcapy.open_live("en0", 65536, True, 100)
    output_pcap = PcapWriter(output_file, append=True, sync=True)
    print(f"Start capturing. Press Ctrl+C to stop.")
    try:
        while True:
            _, packet = cap.next()
            if filter_packet(packet):
                output_pcap.write(packet)
                packet_callback(packet)
    except KeyboardInterrupt:
        print("Capture stopped. Closing the program.")
        cap.close()
        output_pcap.close()


def filter_packet(packet):
    return DNS in Ether(packet)


if __name__ == "__main__":
    output_file = "captured_traffic.pcap"
    main(output_file)
