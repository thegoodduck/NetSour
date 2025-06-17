from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, get_if_addr, arping, hexdump
import os
import time
import curses
from threading import Thread, Lock
from queue import Queue
import nmap
import requests
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import traceback

ifaces = [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
answer = input(f"Enter your interface(detected: {ifaces}) :  ")
numbers_of_packets_processed = 0
autoscroll = True
filters = {"TCP": True, "UDP": True, "ARP": True, "ICMP": True}

def get_location(ip_address):
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
        location_data = {
            "ip": ip_address,
            "city": response.get("city"),
            "region": response.get("region"),
            "country": response.get("country_name")
        }
        return location_data
    except Exception as e:
        return {"error": str(e)}

def autoscroll_thread(lock, current_index, packets, stdscr, selected_packet):
    global autoscroll
    while True:
        if autoscroll:
            with lock:
                height, _ = stdscr.getmaxyx()
                current_index[0] = max(0, len(packets) - height + 3)
                selected_packet[0] = current_index[0]
        time.sleep(0.1)

def handle_input(stdscr, current_index, packets, lock, selected_packet, content_scroll, tab_index, nmap_queue, nmap_results, key_override=None):
    global autoscroll, filters
    while True:
        key = key_override if key_override is not None else stdscr.getch()
        key_override = None  # Reset after use
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
                    if selected_packet[0] >= current_index[0] + height - 2:
                        current_index[0] += 1
            elif key == ord('r'):
                autoscroll = not autoscroll
                if not autoscroll:
                    selected_packet[0] = current_index[0]
            elif key == ord('c'):
                current_index[0] = max(0, selected_packet[0] - height + 3)
            elif key == curses.KEY_PPAGE:
                content_scroll[0] = max(0, content_scroll[0] - (height // 2))
            elif key == curses.KEY_NPAGE:
                content_scroll[0] += height // 2
            elif key == ord('\t'):
                tab_index[0] = (tab_index[0] + 1) % 6  # Now 6 tabs
            elif key == ord('t'):  # Toggle TCP filter
                filters["TCP"] = not filters["TCP"]
            elif key == ord('u'):  # Toggle UDP filter
                filters["UDP"] = not filters["UDP"]
            elif key == ord('a'):  # Toggle ARP filter
                filters["ARP"] = not filters["ARP"]
            elif key == ord('i'):  # Toggle ICMP filter
                filters["ICMP"] = not filters["ICMP"]
            elif key == ord('n'):  # Trigger a manual Nmap scan
                if packets and 0 <= selected_packet[0] < len(packets):
                    packet = packets[selected_packet[0]][1]
                    if IP in packet:
                        src_ip = packet[IP].src
                        if src_ip not in nmap_results:
                            nmap_thread = Thread(target=perform_nmap_scan, args=(src_ip, nmap_queue))
                            nmap_thread.daemon = True
                            nmap_thread.start()

def process_packet(packet):
    return f"Packet: {packet.summary()}"

def perform_nmap_scan(ip, nmap_queue):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-F')
    nmap_queue.put((ip, nm[ip]))

def scan_network(interface):
    try:
        ip_addr = get_if_addr(interface)
        net = ip_addr + "/24"
        ans, _ = arping(net, timeout=2, verbose=0)
        hosts = [(rcv.psrc, rcv.hwsrc) for snd, rcv in ans]
        return hosts
    except Exception as e:
        return [("Error", str(e))]

def ascii_network_map(hosts):
    if not hosts:
        return "No hosts found."
    lines = ["Network Map:"]
    gateway = hosts[0][0]
    lines.append(f"[Gateway] {gateway}")
    for ip, mac in hosts[1:]:
        lines.append(f"  |-- {ip} ({mac})")
    return "\n".join(lines)

def display_packets(stdscr, packet_queue, nmap_queue):
    global autoscroll, filters
    try:
        packets = []
        filtered_packets = []
        current_index = [0]
        selected_packet = [0]
        content_scroll = [0]
        tab_index = [0]
        lock = Lock()
        nmap_lock = Lock()
        nmap_results = {}
        recon_hosts = []
        recon_map = ""
        recon_scanned = [False]
        show_help = [False]

        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Status bar
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Help popup

        autoscroll_t = Thread(target=autoscroll_thread, args=(lock, current_index, filtered_packets, stdscr, selected_packet))
        autoscroll_t.daemon = True
        autoscroll_t.start()

        def handle_input_with_help(*args, **kwargs):
            while True:
                key = stdscr.getch()
                if key == ord('?'):
                    show_help[0] = not show_help[0]
                else:
                    handle_input(*args, **kwargs, key_override=key)
        
        input_t = Thread(target=handle_input_with_help, args=(stdscr, current_index, filtered_packets, lock, selected_packet, content_scroll, tab_index, nmap_queue, nmap_results))
        input_t.daemon = True
        input_t.start()

        while True:
            if not packet_queue.empty():
                new_packet = packet_queue.get()
                packet_info = process_packet(new_packet)
                with lock:
                    packets.append((packet_info, new_packet))
                    if (filters["TCP"] and TCP in new_packet) or \
                       (filters["UDP"] and UDP in new_packet) or \
                       (filters["ARP"] and ARP in new_packet) or \
                       (filters["ICMP"] and ICMP in new_packet):
                        filtered_packets.append((packet_info, new_packet))
                    
                    if IP in new_packet:
                        src_ip = new_packet[IP].src
                        with nmap_lock:
                            if src_ip not in nmap_results:
                                nmap_thread = Thread(target=perform_nmap_scan, args=(src_ip, nmap_queue))
                                nmap_thread.daemon = True
                                nmap_thread.start()

            # Process Nmap results
            if not nmap_queue.empty():
                ip, scan_result = nmap_queue.get()
                with nmap_lock:
                    nmap_results[ip] = scan_result

            # Recon tab logic
            if tab_index[0] == 5 and not recon_scanned[0]:
                recon_hosts.clear()
                recon_hosts.extend(scan_network(answer))
                recon_map = ascii_network_map(recon_hosts)
                recon_scanned[0] = True
            if tab_index[0] != 5:
                recon_scanned[0] = False

            # Refresh screen
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            packet_list_width = width // 3

            # Draw border
            stdscr.attron(curses.color_pair(1))
            stdscr.border('|', '|', '-', '-', '+', '+', '+', '+')
            stdscr.attroff(curses.color_pair(1))

            # Header
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(0, 2, f" NetSour - Packet Analyzer (Tab: {['Summary', 'Content', 'Hexdump', 'Nmap Scan', 'Geo-Ping', 'Recon Map'][tab_index[0]]}) ", curses.A_BOLD)
            stdscr.attroff(curses.color_pair(1))

            # Status bar
            stdscr.attron(curses.color_pair(6))
            status = f"Interface: {answer} | Packets: {len(filtered_packets)} | Autoscroll: {'ON' if autoscroll else 'OFF'} | Press '?' for help"
            stdscr.addstr(height-2, 0, status[:max(0, width-1)])
            stdscr.attroff(curses.color_pair(6))

            # Display active filters
            filter_str = "Filters: "
            for proto, state in filters.items():
                filter_str += f"{proto}: {'ON' if state else 'OFF'}  "
            stdscr.addstr(1, 2, filter_str.strip(), curses.color_pair(1))

            # Packet list box
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(2, 1, "┌" + "─"*(packet_list_width-3) + "┐")
            for i in range(3, height - 5):
                stdscr.addstr(i, 1, "│" + " "*(packet_list_width-3) + "│")
            stdscr.addstr(height-5, 1, "└" + "─"*(packet_list_width-3) + "┘")
            stdscr.attroff(curses.color_pair(3))

            # Packet list
            for i in range(3, height - 5):
                if current_index[0] + i - 3 < len(filtered_packets):
                    packet_info = filtered_packets[current_index[0] + i - 3][0]
                    display_str = f"{current_index[0] + i - 2}. {packet_info}"
                    if len(display_str) > packet_list_width - 4:
                        display_str = display_str[:packet_list_width-7] + "..."
                    color = curses.color_pair(3) if "TCP" in display_str else curses.color_pair(4) if "UDP" in display_str else curses.color_pair(5)
                    if current_index[0] + i - 3 == selected_packet[0]:
                        stdscr.attron(curses.A_REVERSE)
                    stdscr.attron(color)
                    stdscr.addstr(i, 2, display_str[:packet_list_width-4])
                    stdscr.attroff(color)
                    if current_index[0] + i - 3 == selected_packet[0]:
                        stdscr.attroff(curses.A_REVERSE)

            # Draw selected tab content (shifted right)
            if filtered_packets and 0 <= selected_packet[0] < len(filtered_packets):
                packet_info, packet = filtered_packets[selected_packet[0]]
                content_x = packet_list_width + 2
                if tab_index[0] == 0:  # Summary view
                    summary = packet.summary().splitlines()
                    for i, line in enumerate(summary[content_scroll[0]:]):
                        if i + 3 >= height - 5:
                            break
                        stdscr.addstr(i + 3, content_x, line[:width - content_x - 2])
                elif tab_index[0] == 1:  # Content view
                    content = packet.show(dump=True).splitlines()
                    for i, line in enumerate(content[content_scroll[0]:]):
                        if i + 3 >= height - 5:
                            break
                        stdscr.addstr(i + 3, content_x, line[:width - content_x - 2])
                elif tab_index[0] == 2:  # Hexdump view
                    hexdump_lines = hexdump(packet, dump=True).splitlines()
                    for i, line in enumerate(hexdump_lines[content_scroll[0]:]):
                        if i + 3 >= height - 5:
                            break
                        stdscr.addstr(i + 3, content_x, line[:width - content_x - 2])
                elif tab_index[0] == 3:  # Nmap Scan view
                    if IP in packet:
                        src_ip = packet[IP].src
                        with nmap_lock:
                            if src_ip in nmap_results:
                                scan_result = nmap_results[src_ip]
                                scan_lines = [f"Nmap scan results for {src_ip}:"]
                                if 'tcp' in scan_result:
                                    scan_lines.extend([f"Port {port}: {scan_result['tcp'][port]['state']}" for port in scan_result['tcp']])
                                else:
                                    scan_lines.append("No open TCP ports found.")
                                for i, line in enumerate(scan_lines[content_scroll[0]:]):
                                    if i + 3 >= height - 5:
                                        break
                                    stdscr.addstr(i + 3, content_x, line[:width - content_x - 2])
                            else:
                                stdscr.addstr(3, content_x, "No Nmap results available.")
                    else:
                        stdscr.addstr(3, content_x, "No IP information available for this packet.")
                elif tab_index[0] == 4:  # Geolocation info
                    if IP in packet:
                        src_ip = packet[IP].src
                        location_data = get_location(src_ip)
                        location_str = f"IP: {location_data.get('ip', 'N/A')}\n"
                        location_str += f"City: {location_data.get('city', 'N/A')}\n"
                        location_str += f"Region: {location_data.get('region', 'N/A')}\n"
                        location_str += f"Country: {location_data.get('country', 'N/A')}\n"
                        for i, line in enumerate(location_str.splitlines()):
                            if i + 3 >= height - 5:
                                break
                            stdscr.addstr(i + 3, content_x, line[:width - content_x - 2])
                elif tab_index[0] == 5:  # Recon Map tab
                    stdscr.addstr(3, content_x, "Network Recon Map:")
                    lines = recon_map.splitlines()
                    for i, line in enumerate(lines):
                        if i + 4 >= height - 5:
                            break
                        stdscr.addstr(i + 4, content_x, line[:width - content_x - 2])

            # Help popup
            if show_help[0]:
                help_lines = [
                    " NetSour Help ",
                    "q: Quit | r: Toggle autoscroll | Tab: Change tab | n: Nmap scan | t/u/a/i: Toggle filters ",
                    "Up/Down: Navigate | PgUp/PgDn: Scroll content | c: Center view | ?: Toggle help ",
                    "Tab 6: Recon map | Geolocation: Tab 5 | Nmap: Tab 4 | TCP/UDP/ARP/ICMP: Toggle filters ",
                    "Press any key to close this help."
                ]
                popup_w = max(len(line) for line in help_lines) + 4
                popup_h = len(help_lines) + 2
                popup_y = max(2, (height - popup_h) // 2)
                popup_x = max(2, (width - popup_w) // 2)
                stdscr.attron(curses.color_pair(7))
                for i in range(popup_h):
                    stdscr.addstr(popup_y + i, popup_x, " " * popup_w)
                for i, line in enumerate(help_lines):
                    stdscr.addstr(popup_y + i + 1, popup_x + 2, line)
                stdscr.attroff(curses.color_pair(7))

            # Footer
            stdscr.attron(curses.color_pair(2))
            footer_text = "Press '?' for help | 'q' to quit | 'Tab' to change tab | 'r' autoscroll | 'n' Nmap | t/u/a/i: filters"
            stdscr.addstr(height - 1, 0, footer_text[:max(0, width-1)], curses.A_BOLD)
            stdscr.attroff(curses.color_pair(2))

            stdscr.refresh()
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
def main():
    packet_queue = Queue()
    nmap_queue = Queue()

    def packet_sniffer(packet):
        global numbers_of_packets_processed
        packet_queue.put(packet)
        numbers_of_packets_processed += 1

    sniff_thread = Thread(target=sniff, kwargs={"iface": answer, "prn": packet_sniffer})
    sniff_thread.daemon = True
    sniff_thread.start()

    curses.wrapper(display_packets, packet_queue, nmap_queue)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()