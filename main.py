from scapy.all import *
import os
import time
import curses
from threading import Thread
from queue import Queue
from collections import defaultdict
sniffed_packets=0
def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def process_packet(packet):
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

def create_color_pairs():
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Normal text
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Highlighted text
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)  # Alert text
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Status bar
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Title bar
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)  # Errors

def draw_borders(stdscr):
    height, width = stdscr.getmaxyx()
    stdscr.border()
    stdscr.hline(2, 1, curses.ACS_HLINE, width - 2)
    stdscr.hline(height - 3, 1, curses.ACS_HLINE, width - 2)
    stdscr.refresh()

def sniff_packets(packet_queue, interface):
    try:
        sniff(iface=interface, prn=lambda pkt: packet_queue.put(pkt), store=0)
        sniffed_packets+=1
    except Exception as e:
        print(f"Error sniffing packets: {str(e)}")

def detect_dos(packets, threshold=100, time_window=1):
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

def display_packets(stdscr, packet_queue):
    packets = []
    current_index = 0
    auto_scroll = True
    search_mode = False
    search_query = ""
    pad = curses.newpad(10000, 100)

    while True:
        height, width = stdscr.getmaxyx()
        draw_borders(stdscr)

        stdscr.addstr(1, 2, "NetSour - Network Traffic Analyzer", curses.color_pair(2) | curses.A_BOLD)

        visible_packets = height - 7
        pad.clear()
        search_packets = [pkt for pkt in packets if search_query.lower() in pkt[0].lower()] if search_mode else packets
        for i, (packet_info, _) in enumerate(search_packets):
            line = f"{i+1}. {packet_info}"[:width-4]
            attr = curses.color_pair(2) | curses.A_REVERSE if i == current_index else curses.color_pair(1)
            pad.addstr(i, 0, line, attr)

        pad_start = max(0, current_index - visible_packets + 1)
        pad.refresh(pad_start, 0, 4, 1, height - 4, width - 2)

        status = f"Total: {len(packets)} | Displayed: {len(search_packets)} | Current: {current_index + 1} | Auto-scroll: {'ON' if auto_scroll else 'OFF'}"
        stdscr.addstr(height - 2, 2, status[:width-4], curses.color_pair(4))

        menu = "Q:Quit | ↑↓:Scroll | A:Analyze | R:Toggle Auto-scroll | F:Search"
        stdscr.addstr(height - 1, 2, menu[:width-4], curses.color_pair(2))

        stdscr.refresh()

        if not packet_queue.empty():
            new_packet = packet_queue.get()
            # print(f"New packet: {new_packet.summary()}")  # Debugging print
            packet_info = process_packet(new_packet)
            # print(f"Processed packet: {packet_info}")  # Debugging print
            packets.append((packet_info, new_packet))
            if auto_scroll:
                current_index = len(packets) - 1

        key = stdscr.getch()
        if key == ord('q'):
            break
        elif key == curses.KEY_UP and current_index > 0:
            current_index -= 1
        elif key == curses.KEY_DOWN:
            current_index += 1
        elif key == ord('a'):
            analyze_packet(stdscr, packets, current_index)
        elif key == ord('r'):
            auto_scroll = not auto_scroll
        elif key == ord('f'):
            search_mode = not search_mode
            if search_mode:
                stdscr.addstr(height - 1, 2, "Search Query: ")
                curses.echo()
                search_query = stdscr.getstr().decode()
                curses.noecho()
            current_index = 0
            if not search_mode:
                search_query = ""

        if auto_scroll:
            current_index = sniffed_packets - 1
            # print(f"Auto-scroll current index: {current_index}")  # Debugging print

def analyze_packet(stdscr, packets, index):
    try:
        _, packet = packets[index]

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

        stdscr.clear()
        curses.curs_set(0)
        stdscr.refresh()
    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")
        input("\nPress Enter to return...")

def main(stdscr):
    try:
        curses.curs_set(0)
        create_color_pairs()

        if is_root():
            stdscr.addstr(0, 0, "[+] You are root.", curses.color_pair(5))
        else:
            stdscr.addstr(0, 0, "[-] You are not root.", curses.color_pair(6))
        stdscr.addstr(1, 0, "[+] Enter the interface name: ")
        curses.echo()
        interface = stdscr.getstr().decode()
        curses.noecho()

        packet_queue = Queue()
        sniff_thread = Thread(target=sniff_packets, args=(packet_queue, interface))
        sniff_thread.daemon = True
        sniff_thread.start()

        stdscr.addstr(3, 0, "[+] Starting NetSour...", curses.color_pair(5))
        stdscr.refresh()
        stdscr.clear()
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        display_packets(stdscr, packet_queue)
    except Exception as e:
        print(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
