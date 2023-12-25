import unittest
from unittest.mock import patch
from packet_parser import PacketParser


class TestPacketParser(unittest.TestCase):
    @patch('builtins.print')
    @patch('packet_parser.socket.inet_ntoa')
    @patch('packet_parser.time.time')
    def test_parse_packet_and_write_to_pcap(self, mock_time, mock_inet_ntoa):
        output_file = 'test_output.pcap'
        parser = PacketParser(output_file)

        mock_time.return_value = 1622000000.0

        mock_inet_ntoa.side_effect = lambda x: '.'.join(map(str, x))

        test_packet = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02\xd9\x2a\x04\xd2\x00\x08\x00\x09'

        parsed_info = parser.parse_packet(test_packet)
        parser.write_to_pcap(test_packet)

        self.assertIn("Ethernet Frame", parsed_info)
        self.assertIn("IP Header", parsed_info)
        self.assertIn("TCP Header", parsed_info)

        with open(output_file, 'rb') as pcap_file:
            pcap_content = pcap_file.read()
            self.assertTrue(pcap_content.startswith(
                b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
            self.assertTrue(pcap_content[
                            24:28] == b'\x60\x8d\x3f\x61')
            self.assertTrue(pcap_content[
                            28:32] == b'\x10\x35\x00\x00')
            self.assertTrue(
                pcap_content[32:36] == b'\x1c\x00\x00\x00')
            self.assertTrue(
                pcap_content[36:40] == b'\x1c\x00\x00\x00')

        parser.__del__()


if __name__ == '__main__':
    unittest.main()
