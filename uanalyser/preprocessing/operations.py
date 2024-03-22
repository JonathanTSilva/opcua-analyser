import scapy.all as scapy


def calculate_package_time_difference(
    packet: scapy.Packet, first_packet: scapy.Packet
) -> float:
    """Calculate the time difference between the packet and the first packet.

    Args:
        packet (scapy.Packet): The packet to calculate the time difference of.
        first_packet (scapy.Packet): The first packet of a capture.

    Returns:
        The time difference between the packet and the first packet, rounded to 6 decimal places.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/example.pcapng')

        Then, you can use these packets to call the function:

        >>> calculate_package_time_difference(capture[1], capture[0])
        0.00143

        >>> calculate_package_time_difference(capture[4], capture[0])
        0.009839
    """
    return round(float(packet.time) - float(first_packet.time), 6)


def detect_opcua_attack(
    packet: scapy.Packet, server_ip: str, clients_ip: list[str]
) -> bool:
    """Detect if a packet is part of an OPCUA attack.

    Args:
        packet: The packet to be analysed.
        server_ip: The IP address of the OPCUA server.
        clients_ip: List of clients IP addresses.

    Returns:
        True if the packet may be part of an OPCUA attack, False otherwise.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/dos_attack_example.pcapng')

        Then, you can use these packets to call the function:

        >>> detect_opcua_attack(capture[4], '192.168.164.101', ['192.168.164.102'])
        False

        >>> detect_opcua_attack(capture[1966], '192.168.164.101', ['192.168.164.102'])
        True
    """
    if packet.haslayer(scapy.TCP):
        if (
            packet[scapy.IP].dst == server_ip
            and packet[scapy.IP].src not in clients_ip
        ):
            return True
    return False
