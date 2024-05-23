import scapy.all as scapy


def calculate_throughput_in_kbps(
    capture: scapy.PacketList, chronology_packets: list, period: float
) -> list:
    """
    Calculates the throughput in kilobits per second (kbps) for a given capture and chronology.

    Args:
        capture (scapy.PacketList): The captured packets.
        chronology_packets (list): The list of packet chronologically organized and filtered.
        period (float): The duration of the capture period in seconds.

    Returns:
        list: A list of throughput values in kilobits per second (kbps) for each second of the capture period.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/example.pcapng')

        Additionaly, generate a list of packet timestamps and indices:
        >>> initial_time = capture[0].time
        >>> chronology_packets = [(index, round(float(packet.time) - float(initial_time), 6)) for index, packet in enumerate(capture)]

        Then, you can use these packets to call the function:

        >>> calculate_throughput_in_kbps(capture, chronology_packets, 60)
        [0.94921875, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.94921875, 0.0, 0.0, 0.0, 0.216796875, 0.31640625, 0.0, 0.0, 0.0, 0.0, 0.0, 28.056640625, 29.470703125, 26.564453125, 30.283203125, 27.86328125, 29.66796875, 30.798828125, 26.435546875, 29.986328125, 30.373046875, 26.435546875, 30.244140625, 27.208984375, 29.986328125, 31.345703125, 28.396484375, 29.830078125, 26.693359375, 29.857421875, 29.986328125, 28.759765625, 30.611328125, 28.58984375, 30.73828125]
    """
    segment_duration = 1
    throughput_persecond = []
    for second in range(int(period)):
        len_bytes = 0
        for elem in chronology_packets:
            if int(elem[1]) == second * segment_duration:
                len_bytes += len(capture[elem[0]])
            if int(elem[1]) > second * segment_duration:
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


def calculate_round_trip_time(
    chronology_packets: list, flow: str = 'C-S'
) -> list:
    """Calculate the round trip time (RTT) for a given chronology and communication flow.

    Args:
        chronology_packets (list): The list of packet indices, timestamps, source and destination addresses, communication type and the is_opcua flag.
        flow (str, optional): The flow of communication. Defaults to 'C-S'. Acceptable values are: 'C-S' (request: Client to Server; response: Server to Client) and 'A-S' (request: Attacker to Server; response: Server to Attacker)

    Returns:
        list: A list of round trip times (RTTs) for the given flow of communication.

    Raises:
        ValueError: If an unacceptable flow of communication is provided.

    Examples:
        First, you need to generate a list of packet indices, timestamps, source and destination addresses, communication type and the is_opcua flag:

        >>> chronology_packets = [[1003, 27.624441, 'e4:5f:01:2e:1a:b6', 'e4:5f:01:2e:1b:c1', 'Server to Client', True], [1005, 27.626184, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1007, 27.628043, 'e4:5f:01:2e:1a:b6', 'e4:5f:01:2e:1b:c1', 'Server to Client', False], [1009, 27.671676, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1011, 27.730078, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1013, 27.733745, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', False], [1017, 27.735299, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1019, 27.737091, 'e4:5f:01:2e:1a:b6', 'e4:5f:01:2e:1b:c1', 'Server to Client', False], [1021, 27.737336, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1023, 27.739157, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', True], [1962, 32.281199, 'e4:5f:01:2e:1a:b6', 'e4:5f:01:2e:1b:c1', 'Server to Client', False], [1964, 32.281224, 'e4:5f:01:2e:1b:c1', 'e4:5f:01:2e:1a:b6', 'Client to Server', False], [1966, 32.341966, '00:09:5b:bd:64:06', 'e4:5f:01:2e:1a:b6', 'Attacker to Server', True], [1967, 32.342171, 'e4:5f:01:2e:1a:b6', '00:09:5b:bd:64:06', 'Server to Attacker', True], [1969, 32.343023, '00:09:5b:bd:64:06', 'e4:5f:01:2e:1a:b6', 'Attacker to Server', False], [1971, 32.345775, 'e4:5f:01:2e:1a:b6', '00:09:5b:bd:64:06', 'Server to Attacker', True], [1973, 32.346763, '00:09:5b:bd:64:06', 'e4:5f:01:2e:1a:b6', 'Attacker to Server', False], [1975, 32.348871, 'e4:5f:01:2e:1a:b6', '00:09:5b:bd:64:06', 'Server to Attacker', False], [1976, 32.350184, '00:09:5b:bd:64:06', 'e4:5f:01:2e:1a:b6', 'Attacker to Server', True], [1978, 32.352446, 'e4:5f:01:2e:1a:b6', '00:09:5b:bd:64:06', 'Server to Attacker', True], [1979, 32.353344, '00:09:5b:bd:64:06', 'e4:5f:01:2e:1a:b6', 'Attacker to Server', False], [1982, 32.354639, 'e4:5f:01:2e:1a:b6', '00:09:5b:bd:64:06', 'Server to Attacker', True]]

        Test the function:

        >>> calculate_round_trip_time(chronology_packets, 'C-S')
        [[1007, 27.628043, 0.0018590000000031637], [1019, 27.737091, 0.0017919999999982394], [1962, 32.281199, 4.542042000000002]]

        >>> calculate_round_trip_time(chronology_packets, 'C-A')
        Traceback (most recent call last):
        ...
        ValueError: Invalid flow of communication: 'C-A'. Acceptable values are: ['C-S', 'A-S']

        >>> calculate_round_trip_time(chronology_packets, 'A-S')
        [[1967, 32.342171, 0.00020500000000112095], [1971, 32.345775, 0.002752000000000976], [1975, 32.348871, 0.0021079999999997767], [1978, 32.352446, 0.0022620000000017626], [1982, 32.354639, 0.0012949999999989359]]
    """
    types_dict = {
        'C-S': {
            'Request': 'Client to Server',
            'Response': 'Server to Client',
        },
        'A-S': {
            'Request': 'Attacker to Server',
            'Response': 'Server to Attacker',
        },
    }
    requests = {}
    rtts = []

    if flow not in types_dict.keys():
        raise ValueError(
            f"Invalid flow of communication: '{flow}'. Acceptable values are: {list(types_dict.keys())}"
        )

    for entry in chronology_packets:
        index, relative_time, src, dst, comm_type, _ = entry

        if comm_type == types_dict[flow]['Request']:
            requests[(src, dst)] = relative_time
        elif comm_type == types_dict[flow]['Response']:
            request_time = requests.pop((dst, src), None)
            if request_time is not None:
                rtt = relative_time - request_time
                rtts.append([index, relative_time, rtt])

    return rtts


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


def define_communication_type(
    packet: scapy.Packet, server_ip: str, clients_ip: list
) -> str:
    """Define the communication type of a packet. If the packet is from the server to the client, the flow type is 'Server to Client'. If the packet is from the client to the server, the flow type is 'Client to Server'. If the packet is from the attacker to the server, the flow type is 'Attacker to Server'. If the packet is from the server to the attacker, the flow type is 'Server to Attacker'. If the packet is not from any of these flows, the flow type is 'Unknown'.

    Args:
        packet: The packet to be analysed.
        server_ip: The IP address of the OPCUA server.
        clients_ip: List of clients IP addresses.

    Returns:
        The communication type of the packet.

    Examples:
        First, you need to read a packet capture file to get the packets:

        >>> from scapy.all import rdpcap
        >>> capture = rdpcap('tests/assets/0-dos_attack_example.pcapng')

        Then, you can use these packets to call the function:

        >>> define_communication_type(capture[5000], '192.168.164.101', ['192.168.164.102'])
        'Client to Server'

        >>> define_communication_type(capture[97], '192.168.164.101', ['192.168.164.102'])
        'Server to Client'

        >>> define_communication_type(capture[10], '192.168.164.101', ['192.168.164.102'])
        'Unknown'

        >>> define_communication_type(capture[1973], '192.168.164.101', ['192.168.164.102'])
        'Attacker to Server'

        >>> define_communication_type(capture[1978], '192.168.164.101', ['192.168.164.192'])
        'Server to Attacker'
    """
    if packet.haslayer(scapy.TCP):
        if (
            packet[scapy.IP].src == server_ip
            and packet[scapy.IP].dst in clients_ip
        ):
            return 'Server to Client'
        if (
            packet[scapy.IP].dst == server_ip
            and packet[scapy.IP].src in clients_ip
        ):
            return 'Client to Server'
        if detect_opcua_attack(packet, server_ip, clients_ip):
            return 'Attacker to Server'
        if (
            packet[scapy.IP].src in server_ip
            and packet[scapy.IP].dst not in clients_ip
        ):
            return 'Server to Attacker'
    return 'Unknown'


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
