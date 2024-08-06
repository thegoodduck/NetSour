from scapy.all import IP, TCP, UDP, ARP, sniff, hexdump
import os
import time
import curses
from threading import Thread
from queue import Queue
from collections import defaultdict
from typing import List, Tuple, Optional

# Constants
NORMAL_TEXT = 1
HIGHLIGHTED_TEXT = 2
ALERT_TEXT = 3
STATUS_BAR = 4
TITLE_BAR = 5
ERROR_TEXT = 6

class PacketAnalyzer:
    @staticmethod
    def process_packet(packet) -> str:
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    return f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    return f"UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                else:
                    return f"Other IP: {src_ip} -> {dst_ip}, Proto: {proto}"
            elif packet.haslayer(ARP):
                return f"ARP: {packet[ARP].psrc} -> {packet[ARP].pdst}"
            else:
                return f"Other: {packet.summary()}"
        except Exception as e:
            return f"Error processing packet: {str(e)}"

    @staticmethod
    def detect_dos(packets: List[Tuple[str, 'Packet']], threshold: int = 100, time_window: int = 1) -> List[str]:
        try:
            packet_count = defaultdict(int)
            current_time = time.time()

            for _, packet in packets:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    packet_time = packet.time

                    if current_time - packet_time <= time_window:
                        packet_count[src_ip] += 1

            return [ip for ip, count in packet_count.items() if count >= threshold]
        except Exception as e:
            print(f"Error detecting DoS: {str(e)}")
            return []

class NetworkSniffer:
    def __init__(self, interface: str):
        self.interface = interface
        self.packet_queue = Queue()
        self.sniffed_packets = 0

    def start_sniffing(self):
        try:
            sniff(iface=self.interface, prn=self._packet_callback, store=0)
        except Exception as e:
            print(f"Error sniffing packets: {str(e)}")

    def _packet_callback(self, packet):
        self.packet_queue.put(packet)
        self.sniffed_packets += 1

class UserInterface:
    def __init__(self, stdscr, packet_queue: Queue):
        self.stdscr = stdscr
        self.packet_queue = packet_queue
        self.packets: List[Tuple[str, 'Packet']] = []
        self.current_index = 0
        self.auto_scroll = True
        self.search_mode = False
        self.search_query = ""
        self.pad = curses.newpad(10000, 100)

    def setup(self):
        curses.curs_set(0)
        self._create_color_pairs()

    def _create_color_pairs(self):
        curses.init_pair(NORMAL_TEXT, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(HIGHLIGHTED_TEXT, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(ALERT_TEXT, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(STATUS_BAR, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(TITLE_BAR, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(ERROR_TEXT, curses.COLOR_WHITE, curses.COLOR_RED)

    def draw_borders(self):
        height, width = self.stdscr.getmaxyx()
        self.stdscr.border()
        self.stdscr.hline(2, 1, curses.ACS_HLINE, width - 2)
        self.stdscr.hline(height - 3, 1, curses.ACS_HLINE, width - 2)
        self.stdscr.refresh()

    def display_packets(self):
        while True:
            height, width = self.stdscr.getmaxyx()
            self.draw_borders()
            self.display_title()
            visible_packets = height - 7

            search_packets = self._filter_packets() if self.search_mode else self.packets
            self._display_packet_list(search_packets, width)
            
            pad_start = self._calculate_pad_start(search_packets, visible_packets)
            self.pad.refresh(pad_start, 0, 4, 1, height - 4, width - 2)

            self._display_status(search_packets, height, width)
            self._display_menu(height, width)
            
            self.stdscr.refresh()

            self._process_new_packets()
            
            key = self.stdscr.getch()
            self._handle_user_input(key, search_packets, height)
            
            if key == ord('q'):
                break

    def display_title(self):
        self.stdscr.addstr(1, 2, "NetSour - Network Traffic Analyzer", curses.color_pair(HIGHLIGHTED_TEXT) | curses.A_BOLD)

    def _filter_packets(self) -> List[Tuple[str, 'Packet']]:
        return [pkt for pkt in self.packets if self.search_query.lower() in pkt[0].lower()]

    def _display_packet_list(self, packets: List[Tuple[str, 'Packet']], width: int):
        self.pad.clear()
        for i, (packet_info, _) in enumerate(packets):
            line = f"{i+1}. {packet_info}"[:width-4]
            attr = curses.color_pair(HIGHLIGHTED_TEXT) | curses.A_REVERSE if i == self.current_index else curses.color_pair(NORMAL_TEXT)
            self.pad.addstr(i, 0, line, attr)

    def _calculate_pad_start(self, packets: List[Tuple[str, 'Packet']], visible_packets: int) -> int:
        if self.auto_scroll:
            return max(0, len(packets) - visible_packets)
        else:
            return max(0, self.current_index - visible_packets // 2)

    def _display_status(self, search_packets: List[Tuple[str, 'Packet']], height: int, width: int):
        status = f"Total: {len(self.packets)} | Displayed: {len(search_packets)} | Current: {self.current_index + 1} | Auto-scroll: {'ON' if self.auto_scroll else 'OFF'}"
        self.stdscr.addstr(height - 2, 2, status[:width-4], curses.color_pair(STATUS_BAR))

    def _display_menu(self, height: int, width: int):
        menu = "Q:Quit | ↑↓:Scroll | A:Analyze | R:Toggle Auto-scroll | F:Search"
        self.stdscr.addstr(height - 1, 2, menu[:width-4], curses.color_pair(HIGHLIGHTED_TEXT))

    def _process_new_packets(self):
        if not self.packet_queue.empty():
            new_packet = self.packet_queue.get()
            packet_info = PacketAnalyzer.process_packet(new_packet)
            self.packets.append((packet_info, new_packet))
            if self.auto_scroll:
                self.current_index = len(self.packets) - 1

    def _handle_user_input(self, key: int, search_packets: List[Tuple[str, 'Packet']], height: int):
        if key == curses.KEY_UP and self.current_index > 0:
            self.current_index -= 1
            self.auto_scroll = False
        elif key == curses.KEY_DOWN and self.current_index < len(search_packets) - 1:
            self.current_index += 1
            self.auto_scroll = False
        elif key == ord('a'):
            self._analyze_packet(search_packets)
        elif key == ord('r'):
            self.auto_scroll = not self.auto_scroll
        elif key == ord('f'):
            self._toggle_search_mode(height)

    def _toggle_search_mode(self, height: int):
        self.search_mode = not self.search_mode
        self.search_query = ""
        if self.search_mode:
            self.stdscr.addstr(height - 1, 2, "Search Query: ")
            curses.echo()
            self.search_query = self.stdscr.getstr().decode()
            curses.noecho()

    def _analyze_packet(self, search_packets: List[Tuple[str, 'Packet']]):
        try:
            _, packet = search_packets[self.current_index]

            curses.endwin()
            os.system('cls' if os.name == 'nt' else 'clear')

            print("Packet details:")
            print(packet.show(dump=True))

            print("\nPacket content:")
            if packet.haslayer(TCP):
                print(f"TCP: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            elif packet.haslayer(UDP):
                print(f"UDP: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
            hexdump(packet)
            print("\nPress Enter to return...")
            input()

            self.stdscr.clear()
            curses.curs_set(0)
            self.stdscr.refresh()
        except Exception as e:
            print(f"Error analyzing packet: {str(e)}")
            input("\nPress Enter to return...")

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def main(stdscr):
    try:
        ui = UserInterface(stdscr, Queue())
        ui.setup()

        if is_root():
            stdscr.addstr(0, 0, "[+] You are root.", curses.color_pair(TITLE_BAR))
        else:
            stdscr.addstr(0, 0, "[-] You are not root.", curses.color_pair(ERROR_TEXT))
        stdscr.addstr(1, 0, "[+] Enter the interface name: ")
        curses.echo()
        interface = stdscr.getstr().decode()
        curses.noecho()

        sniffer = NetworkSniffer(interface)
        sniff_thread = Thread(target=sniffer.start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()

        stdscr.addstr(3, 0, "[+] Starting NetSour...", curses.color_pair(TITLE_BAR))
        stdscr.refresh()
        stdscr.clear()
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        ui.packet_queue = sniffer.packet_queue
        ui.display_packets()
    except Exception as e:
        print(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
