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
        
        while True:
            try:
                stdscr.clear()
                height, width = stdscr.getmaxyx()
                
                potential_attackers = detect_dos(packets)
                if potential_attackers:
                    stdscr.addstr(0, 0, f"Potential DoS detected from: {', '.join(potential_attackers)}", curses.A_BOLD)
                
                for i in range(1, height - 1):
                    if current_index + i - 1 < len(packets):
                        try:
                            packet_info = packets[current_index + i - 1][0]
                            display_str = f"{current_index + i}. {packet_info}"
                            if len(display_str) > width - 1:
                                display_str = display_str[:width-4] + "..."
                            stdscr.addstr(i, 0, display_str)
                        except curses.error:
                            pass

                try:
                    stdscr.addstr(height-1, 0, "Press 'q' to quit, arrow keys to scroll, 'a' to analyze packet")
                except curses.error:
                    pass

                stdscr.refresh()
                
                if not packet_queue.empty():
                    new_packet = packet_queue.get()
                    packet_info = process_packet(new_packet)
                    packets.append((packet_info, new_packet))
                
                key = stdscr.getch()
                if key == ord('q'):
                    break
                elif key == curses.KEY_UP:
                    if current_index > 0:
                        current_index -= 1
                elif key == curses.KEY_DOWN:
                    if current_index < len(packets) - height + 2:
                        current_index += 1
                elif key == ord('a'):
                    analyze_index = current_index + (height - 2) // 2 - 1
                    if 0 <= analyze_index < len(packets):
                        analyze_packet(stdscr, packets, analyze_index)

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
