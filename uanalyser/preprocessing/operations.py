import scapy.all as scapy


def calculate_throughput_in_kbps(
    capture: scapy.PacketList, chronology: list, period: float
) -> list:
    """
    Calculates the throughput in kilobits per second (kbps) for a given capture and chronology.

    Args:
        capture (scapy.PacketList): The captured packets.
        chronology (list): The list of packet timestamps and indices.
        period (float): The duration of the capture period in seconds.

    Returns:
        list: A list of throughput values in kilobits per second (kbps) for each second of the capture period.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/example.pcapng')

        Additionaly, generate a list of packet timestamps and indices:
        >>> initial_time = capture[0].time
        >>> chronology = [(round(float(packet.time) - float(initial_time), 6), index) for index, packet in enumerate(capture)]

        Then, you can use these packets to call the function:

        >>> calculate_throughput_in_kbps(capture, chronology, 60)
        [0.94921875, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.94921875, 0.0, 0.0, 0.0, 0.216796875, 0.31640625, 0.0, 0.0, 0.0, 0.0, 0.0, 28.056640625, 29.470703125, 26.564453125, 30.283203125, 27.86328125, 29.66796875, 30.798828125, 26.435546875, 29.986328125, 30.373046875, 26.435546875, 30.244140625, 27.208984375, 29.986328125, 31.345703125, 28.396484375, 29.830078125, 26.693359375, 29.857421875, 29.986328125, 28.759765625, 30.611328125, 28.58984375, 30.73828125]
    """
    segment_duration = 1
    throughput_persecond = []
    for second in range(int(period)):
        len_bytes = 0
        for elem in chronology:
            if int(elem[0]) == second * segment_duration:
                len_bytes += len(capture[elem[1]])
            if int(elem[0]) > second * segment_duration:
                break
        throughput_persecond.append(len_bytes)
    return [value / 1024 for value in throughput_persecond]


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


def clear_redundant_data(capture: scapy.PacketList) -> scapy.PacketList:
    """Clear the redundant data from a packet capture.

    Args:
        capture: The packet capture.

    Returns:
        The packet capture without redundant data.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/example.pcapng')

        Then, you can use these packets to call the function:

        >>> clear_redundant_data(capture)
        <PacketList: TCP:3212 UDP:110 ICMP:0 Other:7>
    """
    unique_packets = []
    for packet in capture:
        if packet.time not in [p.time for p in unique_packets]:
            unique_packets.append(packet)
    return scapy.PacketList(unique_packets)


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
        >>> capture = rdpcap('tests/assets/0-dos_attack_example.pcapng')

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


def is_opcua_packet(packet: scapy.Packet, ports: list) -> bool:
    """Check if a packet is an OPC UA packet.

    Args:
        packet: The packet to be analysed.
        ports: List of OPC UA ports.

    Returns:
        True if the packet is an OPC UA packet, False otherwise.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/0-dos_attack_example.pcapng')

        Then, you can use these packets to call the function:

        >>> is_opcua_packet(capture[31], [4840])
        True

        >>> is_opcua_packet(capture[15], [4840])
        False

        >>> is_opcua_packet(capture[733], [4840])
        True
    """
    if packet.haslayer(scapy.IP):
        if packet[scapy.IP].dport in ports or packet[scapy.IP].sport in ports:
            return True
    return False
