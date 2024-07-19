# NetSour

NetSour is a network packet sniffer and analyzer tool built with Python and Scapy.

## Features

- Real-time packet capture and display
- Packet analysis and hexdump view
- DoS (Denial of Service) attack detection
- Support for various protocols (TCP, UDP, ARP, etc.)
- Interactive curses-based user interface

## Requirements

- Python 3.x
- Scapy
- Root/Administrator privileges (for packet sniffing)

## Installation

1. Clone this repository
2. Install the required dependencies:



pip install -r requirements.txt


## Usage

Run the script with root privileges:




sudo python main.py


1. Enter the network interface name when prompted
2. Use arrow keys to navigate through captured packets
3. Press 'a' to analyze a specific packet
4. Press 'q' to quit the application

## Functions

- `is_root()`: Checks if the script is running with root privileges
- `process_packet()`: Extracts and formats packet information
- `sniff_packets()`: Captures network packets using Scapy
- `detect_dos()`: Identifies potential DoS attacks
- `display_packets()`: Manages the main user interface
- `analyze_packet()`: Provides detailed analysis of a selected packet

## Note

This tool is for educational and network administration purposes only. Always obtain proper authorization before monitoring network traffic.

## License

Gpl V3



