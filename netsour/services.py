"""Port -> service name lookup, with a curated table plus /etc/services fallback."""

from __future__ import annotations

import functools

# Curated table: the ports worth naming inline in a packet list. Kept small and
# deliberate so the common case never touches /etc/services.
WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 514: "syslog",
    515: "printer", 520: "rip", 546: "dhcpv6", 547: "dhcpv6", 587: "submission",
    623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "ssdp",
    2049: "nfs", 2082: "cpanel", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "http-alt", 3128: "squid", 3260: "iscsi",
    3306: "mysql", 3389: "rdp", 4369: "epmd", 4500: "ipsec-nat",
    5000: "http-alt", 5060: "sip", 5061: "sips", 5222: "xmpp", 5353: "mdns",
    5432: "postgres", 5555: "adb", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5938: "teamviewer", 6379: "redis", 6443: "kube-api",
    6667: "irc", 8000: "http-alt", 8006: "proxmox", 8080: "http-proxy",
    8086: "influxdb", 8088: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "prometheus", 9092: "kafka", 9200: "elastic",
    9418: "git", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
    50000: "sap",
}

# Ports where credentials or content travel in the clear.
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
                   110: "POP3", 143: "IMAP", 389: "LDAP", 512: "rexec",
                   513: "rlogin", 514: "rsh", 1521: "Oracle", 3306: "MySQL",
                   5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached"}


@functools.lru_cache(maxsize=4096)
def service_name(port: int, proto: str = "tcp") -> str:
    """Return a short service label for a port, or "" when nothing is known."""
    if port in WELL_KNOWN:
        return WELL_KNOWN[port]
    try:
        import socket

        return socket.getservbyport(port, proto)
    except Exception:
        return ""


def port_label(port: int, proto: str = "tcp") -> str:
    """Render a port as `443(https)` when a name exists, else just the number."""
    name = service_name(port, proto)
    return f"{port}({name})" if name else str(port)
