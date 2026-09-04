"""
Common port definitions and service mappings.

This module contains well-known port numbers and their associated services.
"""

from typing import Dict, List

# Well-known ports and their services
COMMON_PORTS: Dict[int, str] = {
    # Web services
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    8000: "http-alt",
    8008: "http-alt",
    8888: "http-alt",
    3000: "http-dev",
    3001: "http-dev",
    5000: "http-dev",
    9000: "http-alt",
    # SSH and remote access
    22: "ssh",
    23: "telnet",
    3389: "rdp",
    5900: "vnc",
    5901: "vnc",
    # FTP
    20: "ftp-data",
    21: "ftp",
    990: "ftps",
    # Email services
    25: "smtp",
    110: "pop3",
    143: "imap",
    993: "imaps",
    995: "pop3s",
    587: "smtp-msa",
    465: "smtps",
    # DNS
    53: "dns",
    853: "dns-over-tls",
    # Database services
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    # Directory services
    389: "ldap",
    636: "ldaps",
    88: "kerberos",
    # Network services
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    # File sharing
    135: "msrpc",
    139: "netbios-ssn",
    445: "smb",
    2049: "nfs",
    # Proxy and load balancing
    1080: "socks",
    3128: "squid",
    8118: "privoxy",
    # Application services
    6443: "kubernetes-api",
    2376: "docker",
    2377: "docker-swarm",
    4243: "docker-api",
    # Gaming and media
    25565: "minecraft",
    27015: "steam",
    # Monitoring and management
    161: "snmp",
    514: "syslog",
    10050: "zabbix",
    9090: "prometheus",
    3000: "grafana",
    # Message queues
    5672: "amqp",
    15672: "rabbitmq-mgmt",
    9092: "kafka",
    # Misc services
    123: "ntp",
    1194: "openvpn",
    500: "ipsec",
    4500: "ipsec-nat",
}

# Additional firewall/security related ports
FIREWALL_PORTS: Dict[int, str] = {
    # Common firewall management ports
    4433: "firewall-mgmt",
    8443: "firewall-web",
    9443: "firewall-api",
    # Load balancer ports
    80: "lb-http",
    443: "lb-https",
    8080: "lb-http-alt",
    8443: "lb-https-alt",
    # WAF specific ports
    8000: "waf-http",
    8001: "waf-https",
    8002: "waf-mgmt",
    # Proxy ports
    3128: "proxy",
    8080: "proxy-alt",
    8118: "proxy-web",
    # VPN ports
    1194: "openvpn",
    1723: "pptp",
    500: "ipsec-ike",
    4500: "ipsec-nat-t",
}

# Top ports to scan by default
TOP_PORTS: List[int] = [
    80,
    443,
    22,
    21,
    25,
    53,
    110,
    143,
    993,
    995,
    587,
    8080,
    8443,
    3389,
    1433,
    3306,
    5432,
    6379,
    389,
    636,
    135,
    139,
    445,
    161,
    1080,
    3128,
    8000,
    8888,
    9000,
]

# Critical security ports that should be monitored
CRITICAL_PORTS: List[int] = [
    22,  # SSH
    23,  # Telnet (insecure)
    135,  # RPC
    139,  # NetBIOS
    445,  # SMB
    1433,  # SQL Server
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
]


def get_service_name(port: int) -> str:
    """
    Get the service name for a given port.

    Args:
        port: Port number

    Returns:
        Service name or 'unknown' if not found
    """
    return COMMON_PORTS.get(port, "unknown")


def get_port_by_service(service: str) -> List[int]:
    """
    Get port numbers for a given service.

    Args:
        service: Service name

    Returns:
        List of port numbers for the service
    """
    return [port for port, svc in COMMON_PORTS.items() if svc == service]


def is_critical_port(port: int) -> bool:
    """
    Check if a port is considered critical for security.

    Args:
        port: Port number

    Returns:
        True if port is critical, False otherwise
    """
    return port in CRITICAL_PORTS


def get_web_ports() -> List[int]:
    """Get list of common web service ports."""
    web_services = ["http", "https", "http-alt", "https-alt", "http-dev"]
    return [port for port, service in COMMON_PORTS.items() if service in web_services]


def get_database_ports() -> List[int]:
    """Get list of common database ports."""
    db_services = ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"]
    return [port for port, service in COMMON_PORTS.items() if service in db_services]


def get_mail_ports() -> List[int]:
    """Get list of common email service ports."""
    mail_services = ["smtp", "pop3", "imap", "imaps", "pop3s", "smtp-msa", "smtps"]
    return [port for port, service in COMMON_PORTS.items() if service in mail_services]


def categorize_ports(ports: List[int]) -> Dict[str, List[int]]:
    """
    Categorize a list of ports by service type.

    Args:
        ports: List of port numbers

    Returns:
        Dictionary with categories as keys and port lists as values
    """
    categories = {
        "web": [],
        "database": [],
        "mail": [],
        "ssh": [],
        "ftp": [],
        "dns": [],
        "other": [],
    }

    web_ports = get_web_ports()
    db_ports = get_database_ports()
    mail_ports = get_mail_ports()

    for port in ports:
        service = get_service_name(port)

        if port in web_ports:
            categories["web"].append(port)
        elif port in db_ports:
            categories["database"].append(port)
        elif port in mail_ports:
            categories["mail"].append(port)
        elif service == "ssh":
            categories["ssh"].append(port)
        elif service in ["ftp", "ftp-data", "ftps"]:
            categories["ftp"].append(port)
        elif service in ["dns", "dns-over-tls"]:
            categories["dns"].append(port)
        else:
            categories["other"].append(port)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}


def get_port_description(port: int) -> str:
    """
    Get a detailed description of what a port is used for.

    Args:
        port: Port number

    Returns:
        Human-readable description of the port's purpose
    """
    descriptions = {
        80: "HTTP - Unencrypted web traffic",
        443: "HTTPS - Encrypted web traffic (SSL/TLS)",
        22: "SSH - Secure Shell for remote access",
        21: "FTP - File Transfer Protocol",
        25: "SMTP - Simple Mail Transfer Protocol",
        53: "DNS - Domain Name System",
        110: "POP3 - Post Office Protocol v3",
        143: "IMAP - Internet Message Access Protocol",
        993: "IMAPS - IMAP over SSL/TLS",
        995: "POP3S - POP3 over SSL/TLS",
        587: "SMTP MSA - Mail Submission Agent",
        8080: "HTTP Alternative - Common alternative HTTP port",
        8443: "HTTPS Alternative - Common alternative HTTPS port",
        3389: "RDP - Remote Desktop Protocol",
        1433: "MSSQL - Microsoft SQL Server",
        3306: "MySQL - MySQL Database Server",
        5432: "PostgreSQL - PostgreSQL Database Server",
        6379: "Redis - Redis In-Memory Database",
        389: "LDAP - Lightweight Directory Access Protocol",
        636: "LDAPS - LDAP over SSL/TLS",
        135: "MS RPC - Microsoft Remote Procedure Call",
        139: "NetBIOS - NetBIOS Session Service",
        445: "SMB - Server Message Block (file sharing)",
        161: "SNMP - Simple Network Management Protocol",
    }

    service = get_service_name(port)
    description = descriptions.get(port, f"{service.upper()} - {service} service")

    if is_critical_port(port):
        description += " [CRITICAL - High security risk if exposed]"

    return description
