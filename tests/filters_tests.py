import unittest
import filters


class TestPacketFilter(unittest.TestCase):
    def test_filter_packet_with_protocol(self):
        packet = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x08\x00\x00\x01'

        filter_func = lambda pkt, eth: filters.filter_protocol(pkt, eth, 0x06)
        self.assertTrue(filters.filter_packet(packet, [filter_func]))

        filter_func = lambda pkt, eth: filters.filter_protocol(pkt, eth, 0x11)
        self.assertFalse(filters.filter_packet(packet, [filter_func]))

    def test_filter_packet_with_src_ip(self):
        packet = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x08\x00\x00\x01'

        filter_func = lambda pkt, eth: filters.filter_src_ip(pkt, eth,
                                                     b'\x08\x00\x00\x01')
        self.assertTrue(filters.filter_packet(packet, [filter_func]))

        filter_func = lambda pkt, eth: filters.filter_src_ip(pkt, eth,
                                                     b'\x08\x00\x00\x02')
        self.assertFalse(filters.filter_packet(packet, [filter_func]))

    def test_filter_packet_with_dest_ip(self):
        packet = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x08\x00\x00\x01'

        filter_func = lambda pkt, eth: filters.filter_dest_ip(pkt, eth,
                                                      b'\x08\x00\x00\x01')
        self.assertTrue(filters.filter_packet(packet, [filter_func]))

        filter_func = lambda pkt, eth: filters.filter_dest_ip(pkt, eth,
                                                      b'\x08\x00\x00\x02')
        self.assertFalse(filters.filter_packet(packet, [filter_func]))

    def test_filter_packet_with_src_port(self):
        packet = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x08\x00\x00\x01'

        filter_func = lambda pkt, eth: filters.filter_src_port(pkt, eth, 10)
        self.assertTrue(filters.filter_packet(packet, [filter_func]))

        filter_func = lambda pkt, eth: filters.filter_src_port(pkt, eth, 20)
        self.assertFalse(filters.filter_packet(packet, [filter_func]))

    def test_filter_packet_with_dest_port(self):
        packet = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x08\x00\x00\x01'

        filter_func = lambda pkt, eth: filters.filter_dest_port(pkt, eth, 1)
        self.assertTrue(filters.filter_packet(packet, [filter_func]))

        filter_func = lambda pkt, eth: filters.filter_dest_port(pkt, eth, 2)
        self.assertFalse(filters.filter_packet(packet, [filter_func]))


if __name__ == '__main__':
    unittest.main()
