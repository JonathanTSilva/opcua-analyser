import os

import scapy.all as scapy
from paths import *
from plot.graphics import *
from preprocessing.file_handling import *
from preprocessing.operations import *

SERVER_IP = '192.168.164.101'
CLIENTS_IPS = ['192.168.164.102']
OPCUA_PORTS = [4840]


def main(pcapng_file):
    """
    Entry point of the program.

    This function analyzes a PCAPNG file containing network traffic data.
    It extracts the attack name, opens the file, and performs various calculations and plotting.

    Returns:
        None
    """

    # Local variables
    chronology_packets = []

    # Extract the attack name
    attack = extract_attack_name(pcapng_file)

    # Open File
    capture = open_pcapng_file(pcapng_file)
    # capture = clear_redundant_data(capture)
    capture_length = len(capture)
    # capture_length = 20

    for index in range(capture_length):
        packet = capture[index]
        first_packet = capture[0]

        # Cut the traffic in 1 minute (60 seconds)
        if packet.time - first_packet.time > 60:
            break

        # Calculate the relative time of each packet
        relative_time = calculate_package_time_difference(packet, first_packet)

        # Define the type of the package: request or response
        comm_type = define_communication_type(packet, SERVER_IP, CLIENTS_IPS)

        # Clear reduntant data and flag OPC UA packets
        if index < 1:
            opcua_flag = is_opcua_packet(packet, OPCUA_PORTS)
            chronology_packets.append(
                [index, 0, packet.src, packet.dst, comm_type, opcua_flag]
            )
        if not any(
            relative_time == sublist[1] for sublist in chronology_packets
        ):
            opcua_flag = is_opcua_packet(packet, OPCUA_PORTS)
            chronology_packets.append(
                [
                    index,
                    relative_time,
                    packet.src,
                    packet.dst,
                    comm_type,
                    opcua_flag,
                ]
            )

        # TODO: Add an exception here
        # Detect the attack
        if (
            detect_opcua_attack(packet, SERVER_IP, CLIENTS_IPS)
            and 'Packet index' not in attack
        ):
            attack['Relative time'] = relative_time
            attack['Packet index'] = index

    # Calculate the throughput in kbps
    period = chronology_packets[-1][1]
    throughput_kbps = calculate_throughput_in_kbps(
        capture, chronology_packets, period
    )
    seconds = list(range(1, len(throughput_kbps) + 1))
    number_of_packets = len(chronology_packets)
    filename = GraphUtils.decode_attack_to_file_name(attack)

    # Calculate the cycle time
    rtts_client_server = calculate_round_trip_time(chronology_packets, 'C-S')
    rtts_attacker_server = calculate_round_trip_time(chronology_packets, 'A-S')

    # Check if performance data CSV file exists before plotting performance data
    csv_file = f'{DATA_PERF}/{filename}.csv'
    if os.path.exists(csv_file):
        plot_performance_data(seconds, attack, filename, is_twiny=False)

    plot_round_trip_time_per_packet(
        rtts_client_server,
        number_of_packets,
        attack,
        filename,
        attacker_rtts=rtts_attacker_server,
        performance=False,
    )
    plot_round_trip_time_per_second(
        rtts_client_server,
        seconds,
        attack,
        filename,
        attacker_rtts=rtts_attacker_server,
        performance=False,
    )
    plot_throughput(throughput_kbps, seconds, attack, filename, performance=False)

    # # Don't close the plot window
    # plt.show()


def process_all_pcapng_files(data_dir):
    """
    Process all the pcapng files in a directory.

    Args:
        data_dir (str): The directory containing the pcapng files.

    Returns:
        None
    """
    files = os.listdir(data_dir)
    files = [item for item in files if item.endswith('.pcapng')]

    for elem in files:
        # global PCAPNG
        # PCAPNG = os.path.join(data_dir, elem)
        pcapng_file = os.path.join(data_dir, elem)
        print(f'Processing {pcapng_file}')
        main(pcapng_file)


if __name__ == '__main__':
    process_all_pcapng_files(DATA_PCAPNG)
