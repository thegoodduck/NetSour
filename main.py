from scapy.all import *
import os
import time
import curses
from threading import Thread, Lock
from queue import Queue
import nmap

numbers_of_packets_processed = 0
autoscroll = True
filters = {"TCP": True, "UDP": True, "ARP": True, "ICMP": True}

def autoscroll_thread(lock, current_index, packets, stdscr, selected_packet):
    global autoscroll
    while True:
        if autoscroll:
            with lock:
                height, _ = stdscr.getmaxyx()
                current_index[0] = max(0, len(packets) - height + 2)
                selected_packet[0] = current_index[0]  # Sync selected packet with visible packet when autoscrolling
        time.sleep(0.1)

def handle_input(stdscr, current_index, packets, lock, selected_packet, content_scroll, tab_index):
    global autoscroll, filters
    while True:
        key = stdscr.getch()
        with lock:
            height, _ = stdscr.getmaxyx()
            if key == ord('q'):
                break
            elif key == curses.KEY_UP and not autoscroll:
                if selected_packet[0] > 0:
                    selected_packet[0] -= 1
                    if selected_packet[0] < current_index[0]:
                        current_index[0] -= 1
            elif key == curses.KEY_DOWN and not autoscroll:
                if selected_packet[0] < len(packets) - 1:
                    selected_packet[0] += 1
                    if selected_packet[0] >= current_index[0] + height - 1:
                        current_index[0] += 1
            elif key == ord('r'):
                autoscroll = not autoscroll
                if not autoscroll:
                    selected_packet[0] = current_index[0]  # Sync selection with visible packet on autoscroll stop
            elif key == ord('c'):
                current_index[0] = max(0, selected_packet[0] - height + 2)
            elif key == curses.KEY_PPAGE:
                content_scroll[0] = max(0, content_scroll[0] - (height // 2))
            elif key == curses.KEY_NPAGE:
                content_scroll[0] += height // 2
            elif key == ord('\t'):
                tab_index[0] = (tab_index[0] + 1) % 4  # Cycle through tabs
            elif key == ord('t'):  # Toggle TCP filter
                filters["TCP"] = not filters["TCP"]
            elif key == ord('u'):  # Toggle UDP filter
                filters["UDP"] = not filters["UDP"]
            elif key == ord('a'):  # Toggle ARP filter
                filters["ARP"] = not filters["ARP"]
            elif key == ord('i'):  # Toggle ICMP filter
                filters["ICMP"] = not filters["ICMP"]

def process_packet(packet):
    return f"Packet: {packet.summary()}"

def perform_nmap_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-F')  # Fast scan
    return nm[ip]

def display_packets(stdscr, packet_queue):
    global autoscroll, filters
    try:
        packets = []
        filtered_packets = []
        current_index = [0]  # Current scroll position in the packet list
        selected_packet = [0]  # Currently selected packet
        content_scroll = [0]  # Scroll position within the packet details
        tab_index = [0]  # Current tab (0: Summary, 1: Content, 2: Hexdump, 3: Nmap Scan)
        lock = Lock()

        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

        autoscroll_t = Thread(target=autoscroll_thread, args=(lock, current_index, filtered_packets, stdscr, selected_packet))
        autoscroll_t.daemon = True
        autoscroll_t.start()

        input_t = Thread(target=handle_input, args=(stdscr, current_index, filtered_packets, lock, selected_packet, content_scroll, tab_index))
        input_t.daemon = True
        input_t.start()

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()

            packet_list_width = width // 3

            # Header
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(0, 0, f"NetSour - Packet Analyzer (Tab: {['Summary', 'Content', 'Hexdump', 'Nmap Scan'][tab_index[0]]})", curses.A_BOLD)
            stdscr.attroff(curses.color_pair(1))

            # Display active filters
            filter_str = "Filters: "
            for proto, state in filters.items():
                filter_str += f"{proto}: {'ON' if state else 'OFF'}  "
            stdscr.addstr(1, 0, filter_str.strip(), curses.color_pair(1))

            # Packet list
            for i in range(2, height):
                if current_index[0] + i - 2 < len(filtered_packets):
                    try:
                        packet_info = filtered_packets[current_index[0] + i - 2][0]
                        display_str = f"{current_index[0] + i - 1}. {packet_info}"
                        if len(display_str) > packet_list_width - 1:
                            display_str = display_str[:packet_list_width-4] + "..."
                        color = curses.color_pair(3) if "TCP" in display_str else curses.color_pair(4) if "UDP" in display_str else curses.color_pair(5)
                        if current_index[0] + i - 2 == selected_packet[0]:
                            stdscr.attron(curses.A_REVERSE)  # Highlight the selected packet
                        stdscr.attron(color)
                        stdscr.addstr(i, 0, display_str[:packet_list_width-1])
                        stdscr.attroff(color)
                        if current_index[0] + i - 2 == selected_packet[0]:
                            stdscr.attroff(curses.A_REVERSE)
                    except curses.error:
                        pass

            # Draw selected tab content
            if filtered_packets and 0 <= selected_packet[0] < len(filtered_packets):
                packet_info, packet = filtered_packets[selected_packet[0]]
                
                if tab_index[0] == 0:  # Summary view
                    summary = packet.summary().splitlines()
                    for i, line in enumerate(summary[content_scroll[0]:]):
                        if i + 2 >= height:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])

                elif tab_index[0] == 1:  # Detailed content view
                    packet_content = packet.show(dump=True).splitlines()
                    for i, line in enumerate(packet_content[content_scroll[0]:]):
                        if i + 2 >= height:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])

                elif tab_index[0] == 2:  # Hexdump view
                    packet_hexdump = hexdump(packet, dump=True).splitlines()
                    for i, line in enumerate(packet_hexdump[content_scroll[0]:]):
                        if i + 2 >= height:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])

                elif tab_index[0] == 3:  # Nmap Scan view
                    if IP in packet:
                        src_ip = packet[IP].src
                        scan_result = perform_nmap_scan(src_ip)
                        scan_lines = [f"Nmap scan results for {src_ip}:"]
                        scan_lines.extend([f"Port {port}: {scan_result['tcp'][port]['state']}" for port in scan_result['tcp']])
                        for i, line in enumerate(scan_lines[content_scroll[0]:]):
                            if i + 2 >= height:
                                break
                            stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])
                    else:
                        stdscr.addstr(2, packet_list_width + 1, "No IP information available for this packet")

            # Footer with instructions
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(height-1, 0, "Press 'q' to quit, 'r' to toggle autoscroll, arrows to scroll/select, 'c' to jump to current, 't/u/a/i' to toggle filters, Tab to switch views")
            stdscr.attroff(curses.color_pair(1))
            stdscr.refresh()

            if not packet_queue.empty():
                new_packet = packet_queue.get()
                packet_info = process_packet(new_packet)
                with lock:
                    packets.append((packet_info, new_packet))
                    if filters["TCP"] and new_packet.haslayer(TCP):
                        filtered_packets.append((packet_info, new_packet))
                    elif filters["UDP"] and new_packet.haslayer(UDP):
                        filtered_packets.append((packet_info, new_packet))
                    elif filters["ARP"] and new_packet.haslayer(ARP):
                        filtered_packets.append((packet_info, new_packet))
                    elif filters["ICMP"] and new_packet.haslayer(ICMP):
                        filtered_packets.append((packet_info, new_packet))

            time.sleep(0.1)

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
            stdscr.addstr(0, 0, "[+] You are root.", curses.color_pair(4))
        else:
            stdscr.addstr(0, 0, "[-] You are not root.", curses.color_pair(2))
        stdscr.addstr(1, 0, "[+] Enter the interface name: ", curses.color_pair(1))
        curses.echo()
        interface = stdscr.getstr().decode()
        curses.noecho()

        packet_queue = Queue()
        sniff_thread = Thread(target=packet_sniffer, args=(packet_queue,))
        sniff_thread.daemon = True
        sniff_thread.start()
        
        stdscr.addstr(3, 0, "[+] Starting NetSour...", curses.color_pair(1))
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
