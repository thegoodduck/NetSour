from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, sniff
import os
import time
import curses
from threading import Thread
from queue import Queue
from collections import defaultdict

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        print("Error: Unable to determine root status. This function may not be supported on your operating system.")
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
                packet_info = f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info = f"UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            else:
                packet_info = f"Other IP: {src_ip} -> {dst_ip}, Proto: {proto}"
        elif packet.haslayer(ARP):
            packet_info = f"ARP: {packet[ARP].psrc} -> {packet[ARP].pdst}"
        else:
            packet_info = f"Other: {packet.summary()}"
        return packet_info
    except Exception as e:
        return f"Error processing packet: {str(e)}"
def create_color_pairs():
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Normal text
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Highlighted text
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)  # Alert text
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Status bar

def draw_borders(stdscr):
    height, width = stdscr.getmaxyx()
    stdscr.border()
    stdscr.hline(2, 1, curses.ACS_HLINE, width - 2)
    stdscr.hline(height - 3, 1, curses.ACS_HLINE, width - 2)
    stdscr.refresh()

def sniff_packets(packet_queue, interface):
    try:
        sniff(iface=interface, prn=lambda pkt: packet_queue.put(pkt), store=0)
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
        
        potential_attackers = [ip for ip, count in packet_count.items() if count >= threshold]
        return potential_attackers
    except Exception as e:
        print(f"Error detecting DoS: {str(e)}")
        return []

# Here magic happens: 1 time on around 5 up/down wont work(at) least wth my keyboard
def display_packets(stdscr, packet_queue):
    try:
        packets = []
        current_index = 0
        search_term = ""
        auto_scroll = False
        
        pad = curses.newpad(10000, 100)  # Create a large pad for smooth scrolling
        
        while True:
            try:
                height, width = stdscr.getmaxyx()
                draw_borders(stdscr)
                
                # Display title
                stdscr.addstr(1, 2, "NetSour - Network Traffic Analyzer", curses.color_pair(2) | curses.A_BOLD)
                
                # Display potential DoS attackers
                potential_attackers = detect_dos(packets)
                if potential_attackers:
                    alert = f"Potential DoS detected from: {', '.join(potential_attackers)}"
                    stdscr.addstr(3, 2, alert[:width-4], curses.color_pair(3) | curses.A_BOLD)
                
                # Display packet list
                visible_packets = height - 7
                for i in range(visible_packets):
                    if current_index + i < len(packets):
                        packet_info = packets[current_index + i][0]
                        if search_term.lower() in packet_info.lower():
                            if i == 0:  # Highlight the selected packet
                                pad.addstr(current_index + i, 0, f"{current_index + i + 1}. {packet_info}"[:width-4], curses.color_pair(2) | curses.A_REVERSE)
                            else:
                                pad.addstr(current_index + i, 0, f"{current_index + i + 1}. {packet_info}"[:width-4], curses.color_pair(1))
                
                pad.refresh(current_index, 0, 4, 1, height - 4, width - 2)
                
                # Display status bar
                status = f"Total: {len(packets)} | Current: {current_index + 1} | Search: {search_term} | Auto-scroll: {'ON' if auto_scroll else 'OFF'}"
                stdscr.addstr(height - 2, 2, status[:width-4], curses.color_pair(4))
                
                # Display menu
                menu = "Q:Quit | ↑↓:Scroll | A:Analyze | S:Search | C:Clear search | R:Toggle Auto-scroll"
                stdscr.addstr(height - 1, 2, menu[:width-4], curses.color_pair(2))
                
                stdscr.refresh()
                
                if not packet_queue.empty():
                    new_packet = packet_queue.get()
                    packet_info = process_packet(new_packet)
                    packets.append((packet_info, new_packet))
                    if auto_scroll:
                        current_index = max(0, len(packets) - visible_packets)
                
                key = stdscr.getch()
                if key == ord('q'):
                    break
                elif key == curses.KEY_UP and current_index > 0:
                    current_index -= 1
                elif key == curses.KEY_DOWN and current_index < len(packets) - 1:
                    current_index += 1
                elif key == ord('a'):
                    analyze_packet(stdscr, packets, current_index)
                elif key == ord('s'):
                    try:

                        print('Search is a work in progress. Please wait for future updates.')                        
                        curses.echo()
                        stdscr.addstr(height - 1, 2, "Search: " + " " * (width - 10))
                        stdscr.refresh()
                        search_term = stdscr.getstr(height - 1, 10, 20).decode()
                    except curses.error:
                        search_term = ""
                    finally:
                        curses.noecho()
                elif key == ord('c'):
                    search_term = ""
                elif key == ord('r'):
                    auto_scroll = not auto_scroll

            except Exception as e:
                stdscr.addstr(height-1, 0, f"Error: {str(e)}")
                stdscr.refresh()
                time.sleep(2)
    except Exception as e:
        print(f"Error in display_packets: {str(e)}")




def analyze_packet(stdscr, packets, index):
    try:
        _, packet = packets[index]
        
        curses.endwin()
        
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("Packet details:")
        print(packet.show(dump=True))
        
        print("\n(^^^Packet details up here^^^)Packet content:")
        if packet.haslayer(TCP):
            print(f"TCP: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
        try:
            hexdump(packet)
        except NameError:
            print("Error: hexdump function is not available.")
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
        if is_root():
            stdscr.addstr(0, 0, "[+] You are root.")
        else:
            stdscr.addstr(0, 0, "[-] You are not root.")
        stdscr.addstr(1, 0, "[+] Enter the interface name: ")
        curses.echo()
        interface = stdscr.getstr().decode()
        curses.noecho()

        packet_queue = Queue()
        sniff_thread = Thread(target=sniff_packets, args=(packet_queue, interface))
        sniff_thread.daemon = True
        sniff_thread.start()
        
        stdscr.addstr(3, 0, "[+] Starting NetSour...")
        stdscr.refresh()
        time.sleep(1)
        
        display_packets(stdscr, packet_queue)
    except Exception as e:
        print(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
