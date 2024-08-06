import unittest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, UDP, ARP
from main import PacketAnalyzer, NetworkSniffer, UserInterface, is_root
from queue import Queue

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

class TestPacketAnalyzer(unittest.TestCase):

    def test_process_packet_tcp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, TCP]
        mock_packet.__getitem__.side_effect = lambda x: {
            IP: MagicMock(src='192.168.1.1', dst='192.168.1.2'),
            TCP: MagicMock(sport=12345, dport=80)
        }[x]
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "TCP: 192.168.1.1:12345 -> 192.168.1.2:80")

    def test_process_packet_udp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x in [IP, UDP]
        mock_packet.__getitem__.side_effect = lambda x: {
            IP: MagicMock(src='192.168.1.1', dst='192.168.1.2'),
            UDP: MagicMock(sport=53, dport=12345)
        }[x]
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "UDP: 192.168.1.1:53 -> 192.168.1.2:12345")

    def test_process_packet_other_ip(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == IP
        mock_packet.__getitem__.return_value = MagicMock(src='192.168.1.1', dst='192.168.1.2', proto=1)
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "Other IP: 192.168.1.1 -> 192.168.1.2, Proto: 1")

    def test_process_packet_arp(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda x: x == ARP
        mock_packet.__getitem__.return_value = MagicMock(psrc='192.168.1.1', pdst='192.168.1.2')
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "ARP: 192.168.1.1 -> 192.168.1.2")

    def test_process_packet_other(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        mock_packet.summary.return_value = "Unknown packet"
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "Other: Unknown packet")

    def test_process_packet_exception(self):
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = Exception("Test exception")
        result = PacketAnalyzer.process_packet(mock_packet)
        self.assertEqual(result, "Error processing packet: Test exception")

    def test_detect_dos_no_attack(self):
        packets = [
            (None, MagicMock(haslayer=lambda x: x == IP, time=100, __getitem__=lambda x: MagicMock(src='192.168.1.1'))),
            (None, MagicMock(haslayer=lambda x: x == IP, time=101, __getitem__=lambda x: MagicMock(src='192.168.1.2'))),
        ]
        with patch('time.time', return_value=102):
            result = PacketAnalyzer.detect_dos(packets, threshold=10, time_window=5)
        self.assertEqual(result, [])

    def test_detect_dos_exception(self):
        packets = MagicMock()
        packets.__iter__.side_effect = Exception("Test exception")
        with patch('builtins.print') as mock_print:
            result = PacketAnalyzer.detect_dos(packets)
        self.assertEqual(result, [])
        mock_print.assert_called_once_with("Error detecting DoS: Test exception")

class TestNetworkSniffer(unittest.TestCase):
    def test_init(self):
        sniffer = NetworkSniffer("eth0")
        self.assertEqual(sniffer.interface, "eth0")
        self.assertEqual(sniffer.sniffed_packets, 0)

    @patch('main.sniff')
    def test_start_sniffing(self, mock_sniff):
        sniffer = NetworkSniffer("eth0")
        sniffer.start_sniffing()
        mock_sniff.assert_called_once_with(iface="eth0", prn=sniffer._packet_callback, store=0)

    def test_packet_callback(self):
        sniffer = NetworkSniffer("eth0")
        mock_packet = MagicMock()
        sniffer._packet_callback(mock_packet)
        self.assertEqual(sniffer.sniffed_packets, 1)
        self.assertFalse(sniffer.packet_queue.empty())

class TestUserInterface(unittest.TestCase):
    def test_init(self):
        mock_stdscr = MagicMock()
        mock_queue = Queue()
        ui = UserInterface(mock_stdscr, mock_queue)
        self.assertEqual(ui.current_index, 0)
        self.assertTrue(ui.auto_scroll)
        self.assertFalse(ui.search_mode)
        self.assertEqual(ui.search_query, "")

    def test_filter_packets(self):
        mock_stdscr = MagicMock()
        mock_queue = Queue()
        ui = UserInterface(mock_stdscr, mock_queue)
        ui.packets = [("TCP packet", None), ("UDP packet", None), ("ARP packet", None)]
        ui.search_query = "tcp"
        filtered = ui._filter_packets()
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0][0], "TCP packet")

    def test_calculate_pad_start(self):
        mock_stdscr = MagicMock()
        mock_queue = Queue()
        ui = UserInterface(mock_stdscr, mock_queue)
        ui.packets = [("Packet 1", None), ("Packet 2", None), ("Packet 3", None)]
        ui.auto_scroll = True
        self.assertEqual(ui._calculate_pad_start(ui.packets, 2), 1)
        ui.auto_scroll = False
        ui.current_index = 1
        self.assertEqual(ui._calculate_pad_start(ui.packets, 2), 0)

    def test_process_new_packets(self):
        mock_stdscr = MagicMock()
        mock_queue = Queue()
        ui = UserInterface(mock_stdscr, mock_queue)
        mock_packet = MagicMock()
        ui.packet_queue.put(mock_packet)
        with patch('main.PacketAnalyzer.process_packet', return_value="Test packet"):
            ui._process_new_packets()
        self.assertEqual(len(ui.packets), 1)
        self.assertEqual(ui.packets[0][0], "Test packet")

if __name__ == '__main__':
    unittest.main()
