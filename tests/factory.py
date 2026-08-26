"""Packet builders shared by the tests.

Every packet is round-tripped through bytes so it looks exactly like something
that came off the wire - unbuilt scapy packets have `None` in computed fields
and behave differently from captured ones.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

CLIENT_MAC = "aa:bb:cc:00:00:01"
SERVER_MAC = "aa:bb:cc:00:00:02"


def wire(packet):
    """Serialise and re-parse, as a live capture would deliver it."""
    return packet.__class__(bytes(packet))


def tcp(src="192.168.1.10", dst="192.168.1.20", sport=40000, dport=80,
        flags="S", payload=b""):
    packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst)
              / TCP(sport=sport, dport=dport, flags=flags))
    if payload:
        packet /= Raw(load=payload)
    return wire(packet)


def udp(src="192.168.1.10", dst="192.168.1.20", sport=40000, dport=1234,
        payload=b"x"):
    return wire(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst)
                / UDP(sport=sport, dport=dport) / Raw(load=payload))


def dns_query(name="example.com", src="192.168.1.10", dst="1.1.1.1",
              dport=53):
    return wire(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst)
                / UDP(sport=40000, dport=dport)
                / DNS(rd=1, qd=DNSQR(qname=name)))


def dns_response(name="example.com", rdata="93.184.216.34", rcode=0):
    return wire(Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src="1.1.1.1", dst="192.168.1.10")
                / UDP(sport=53, dport=40000)
                / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=name),
                      an=DNSRR(rrname=name, rdata=rdata)))


def arp(psrc="192.168.1.1", hwsrc=SERVER_MAC, op=2, pdst="192.168.1.10"):
    return wire(Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst))


def icmp(src="192.168.1.10", dst="192.168.1.1", payload=b""):
    packet = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src, dst=dst)
              / ICMP())
    if payload:
        packet /= Raw(load=payload)
    return wire(packet)


def tls_client_hello(sni="example.com", dst="93.184.216.34", sport=50000):
    """A minimal but structurally valid ClientHello carrying an SNI extension."""
    host = sni.encode()
    server_name = (b"\x00" + len(host).to_bytes(2, "big") + host)
    ext_body = (len(server_name)).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(ext_body).to_bytes(2, "big") + ext_body
    body = (b"\x03\x03" + bytes(32) + b"\x00"          # version, random, no sid
            + b"\x00\x02\x13\x01"                       # one cipher suite
            + b"\x01\x00"                               # one compression method
            + len(extension).to_bytes(2, "big") + extension)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return tcp(dst=dst, sport=sport, dport=443, flags="PA", payload=record)


def dns_response_from(server, client, name, rdata="93.184.216.34"):
    """A resolver answering a lookup - the name belongs to the *target*."""
    return wire(Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src=server, dst=client) / UDP(sport=53, dport=40000)
                / DNS(qr=1, qd=DNSQR(qname=name),
                      an=DNSRR(rrname=name, rdata=rdata)))


def mdns_announce(src, hostname):
    """A device publishing an A record for its own name and address."""
    return wire(Ether(src=CLIENT_MAC, dst="01:00:5e:00:00:fb")
                / IP(src=src, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                / DNS(qr=1, an=DNSRR(rrname=f"{hostname}.local", type="A",
                                     rdata=src)))


def mdns_service(src, service="_googlecast"):
    """A DNS-SD advertisement: says what it offers, not what it is called."""
    name = f"{service}._tcp.local"
    return wire(Ether(src=CLIENT_MAC, dst="01:00:5e:00:00:fb")
                / IP(src=src, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                / DNS(qr=1, qd=DNSQR(qname=name),
                      an=DNSRR(rrname=name, type="PTR",
                               rdata=f"device.{name}")))


def dhcp_request(src, hostname):
    """A DHCP request carrying option 12 - the device naming itself."""
    return wire(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=src, dst="255.255.255.255") / UDP(sport=68, dport=67)
                / BOOTP() / DHCP(options=[("message-type", "request"),
                                          ("hostname", hostname.encode()),
                                          "end"]))
