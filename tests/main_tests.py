import unittest
from unittest.mock import patch, MagicMock
from main import main, is_valid_ip, send_test_packet


class TestNetworkCapture(unittest.TestCase):
    @patch('builtins.print')
    @patch('network_capture.socket.socket')
    @patch('network_capture.PacketParser')
    @patch('network_capture.filter_packet')
    @patch('network_capture.send_test_packet')
    def test_main(self, mock_send_test_packet, mock_filter_packet,
                  mock_PacketParser, mock_socket, mock_print):
        mock_socket_instance = mock_socket.return_value
        mock_PacketParser_instance = mock_PacketParser.return_value

        # Simulate KeyboardInterrupt to exit the loop
        mock_socket_instance.recvfrom.side_effect = KeyboardInterrupt

        # Call the main function
        main("output.pcap", "*", "*", "*", False)

        # Assertions
        mock_socket.assert_called_with(
            main.socket.AF_PACKET, main.socket.SOCK_RAW,
            main.socket.ntohs(0x0003)
        )
        mock_PacketParser.assert_called_with("output.pcap")
        mock_print.assert_called_with("Start capturing. Press Ctrl+C to stop.")
        mock_send_test_packet.assert_not_called()
        mock_socket_instance.recvfrom.assert_called_once_with(2048)
        mock_filter_packet.assert_called_once_with(
            mock_socket_instance.recvfrom()[0], MagicMock())

        mock_PacketParser_instance.parse_packet.assert_called_once()
        mock_PacketParser_instance.write_to_pcap.assert_called_once()
        mock_socket_instance.close.assert_called_once()
        mock_print.assert_any_call(" Capture stopped.")
        mock_print.assert_any_call("Closing the program.")

    @patch('network_capture.sendp')
    def test_send_test_packet(self, mock_sendp):
        send_test_packet()
        mock_sendp.assert_called_once()

    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertFalse(is_valid_ip("invalid_ip"))


if __name__ == '__main__':
    unittest.main()
