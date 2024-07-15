import unittest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, UDP, ARP
from main import process_packet, detect_dos, is_root

class TestMainFunctions(unittest.TestCase):

    def test_is_root_true(self):
        with patch('os.geteuid', return_value=0):
            self.assertTrue(is_root())

    def test_is_root_false(self):
        with patch('os.geteuid', return_value=1000):
            self.assertFalse(is_root())

    def test_is_root_attribute_error(self):
        with patch('os.geteuid', side_effect=AttributeError):
            self.assertFalse(is_root())

    def test_process_packet_tcp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, TCP]
        mock_packet.__getitem__.side_effect = lambda x: {
            IP: MagicMock(src='192.168.1.1', dst='192.168.1.2'),
            TCP: MagicMock(sport=12345, dport=80)
        }[x]
        result = process_packet(mock_packet)
        self.assertEqual(result, "TCP: 192.168.1.1:12345 -> 192.168.1.2:80")

    def test_process_packet_udp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, UDP]
        mock_packet.__getitem__.side_effect = lambda x: {
            IP: MagicMock(src='192.168.1.1', dst='192.168.1.2'),
            UDP: MagicMock(sport=53, dport=12345)
        }[x]
        result = process_packet(mock_packet)
        self.assertEqual(result, "UDP: 192.168.1.1:53 -> 192.168.1.2:12345")

    def test_process_packet_other_ip(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == IP
        mock_packet.__getitem__.return_value = MagicMock(src='192.168.1.1', dst='192.168.1.2', proto=1)
        result = process_packet(mock_packet)
        self.assertEqual(result, "Other IP: 192.168.1.1 -> 192.168.1.2, Proto: 1")

    def test_process_packet_arp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == ARP
        mock_packet.__getitem__.return_value = MagicMock(psrc='192.168.1.1', pdst='192.168.1.2')
        result = process_packet(mock_packet)
        self.assertEqual(result, "ARP: 192.168.1.1 -> 192.168.1.2")

    def test_process_packet_other(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        mock_packet.summary.return_value = "Unknown packet"
        result = process_packet(mock_packet)
        self.assertEqual(result, "Other: Unknown packet")

    def test_process_packet_exception(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = Exception("Test exception")
        result = process_packet(mock_packet)
        self.assertEqual(result, "Error processing packet: Test exception")

    def test_detect_dos_no_attack(self):
        packets = [
            (None, MagicMock(haslayer=lambda x: x == IP, time=100, __getitem__=lambda x: MagicMock(src='192.168.1.1'))),
            (None, MagicMock(haslayer=lambda x: x == IP, time=101, __getitem__=lambda x: MagicMock(src='192.168.1.2'))),
        ]
        with patch('time.time', return_value=102):
            result = detect_dos(packets, threshold=10, time_window=5)
        self.assertEqual(result, [])
    # def test_detect_dos_attack(self):
    #     packets = [
    #         (None, MagicMock(haslayer=lambda x: x == IP, time=100, __getitem__=lambda x: MagicMock(src='192.168.1.1'))),
    #         (None, MagicMock(haslayer=lambda x: x == IP, time=101, __getitem__=lambda x: MagicMock(src='192.168.1.2'))),
    #     ]
    #     with patch('time.time', return_value=102):
    #         result = detect_dos(packets, threshold=1, time_window=5)

    #     self.assertEqual(result, ['192.168.1.1', '192.168.1.2'])    
    def test_detect_dos_exception(self):
        packets = MagicMock()
        packets.__iter__.side_effect = Exception("Test exception")
        with patch('builtins.print') as mock_print:
            result = detect_dos(packets)
        self.assertEqual(result, [])
        mock_print.assert_called_once_with("Error detecting DoS: Test exception")

if __name__ == '__main__':
    unittest.main()
