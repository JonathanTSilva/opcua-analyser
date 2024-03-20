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
