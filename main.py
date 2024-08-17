from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, sniff
import os
import time
import curses
from threading import Thread, Lock
from queue import Queue
from collections import defaultdict

numbers_of_packets_processed = 0
autoscroll = True

def autoscroll_thread(lock, current_index, packets, stdscr):
    global autoscroll
    while True:
        if autoscroll:
            with lock:
                height, _ = stdscr.getmaxyx()
                current_index[0] = max(0, len(packets) - height + 2)
        time.sleep(0.1)

def handle_input(stdscr, current_index, packets, lock):
    global autoscroll
    while True:
        key = stdscr.getch()
        with lock:
            height, _ = stdscr.getmaxyx()
            if key == ord('q'):
                break
            elif key == curses.KEY_UP and not autoscroll:
                if current_index[0] > 0:
                    current_index[0] -= 1
            elif key == curses.KEY_DOWN and not autoscroll:
                if current_index[0] < len(packets) - height + 2:
                    current_index[0] += 1
            elif key == ord("r"):
                autoscroll = not autoscroll

def process_packet(packet):
    return f"Packet: {packet.summary()}"

def detect_dos(packets):
    # This is a placeholder function. Implement your own DoS detection logic here.
    return []

def analyze_packet(stdscr, packets, analyze_index):
    packet_info, packet = packets[analyze_index]
    stdscr.clear()
    stdscr.addstr(0, 0, f"Analyzing packet {analyze_index}: {packet_info}", curses.A_BOLD)
    stdscr.addstr(1, 0, f"Full packet: {packet.show(dump=True)}")
    stdscr.addstr(2, 0, "Press any key to return...")
    stdscr.refresh()
    stdscr.getch()

def display_packets(stdscr, packet_queue):
    global autoscroll
    try:
        packets = []
        current_index = [0]  # Use a list to allow modification in the thread
        lock = Lock()

        autoscroll_t = Thread(target=autoscroll_thread, args=(lock, current_index, packets, stdscr))
        autoscroll_t.daemon = True
        autoscroll_t.start()

        input_t = Thread(target=handle_input, args=(stdscr, current_index, packets, lock))
        input_t.daemon = True
        input_t.start()

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            potential_attackers = detect_dos(packets)
            if potential_attackers:
                stdscr.addstr(0, 0, f"Potential DoS detected from: {', '.join(potential_attackers)}", curses.A_BOLD)
            
            for i in range(1, height - 1):
                if current_index[0] + i - 1 < len(packets):
                    try:
                        packet_info = packets[current_index[0] + i - 1][0]
                        display_str = f"{current_index[0] + i}. {packet_info}"
                        if len(display_str) > width - 1:
                            display_str = display_str[:width-4] + "..."
                        stdscr.addstr(i, 0, display_str)
                    except curses.error:
                        pass

            stdscr.addstr(height-1, 0, "Press 'q' to quit, arrow keys to scroll, 'a' to analyze packet")
            stdscr.refresh()
            
            if not packet_queue.empty():
                new_packet = packet_queue.get()
                packet_info = process_packet(new_packet)
                with lock:
                    packets.append((packet_info, new_packet))
            
            # Add a small delay to slow down the refresh rate
            time.sleep(0.1)  # Adjust this value to control the refresh rate
                    
    except Exception as e:
        print(f"Error in display_packets: {str(e)}")

def packet_sniffer(packet_queue):
    def packet_handler(packet):
        packet_queue.put(packet)
    
    sniff(prn=packet_handler, store=False)

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

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
        sniff_thread = Thread(target=packet_sniffer, args=(packet_queue,))
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
