import matplotlib.pyplot as plt
import scapy.all as scapy
from paths import *
from preprocessing.file_handling import *
from preprocessing.operations import *

SERVER_IP = '192.168.164.101'
CLIENTS_IPS = ['192.168.164.102']
OPCUA_PORTS = [4840]
PCAPNG = f'{TESTS_ASSETS}/0-dos_attack_example.pcapng'
# PCAPNG = f'{DATA}/2-dos_function_call_null_deref.pcapng'


def main():
    # Local variables
    chronology_list = []
    source_list = []
    destination_list = []
    opcua_packets_index = []

    # Extract the attack name
    attack = extract_attack_name(PCAPNG)

    # Open File
    capture = open_pcapng_file(PCAPNG)
    # capture = clear_redundant_data(capture)
    capture_length = len(capture)
    # capture_length = 20

    for index in range(capture_length):
        packet = capture[index]
        first_packet = capture[0]

        # Cut the traffic in 1 minute (60 seconds)
        if packet.time - first_packet.time > 60:
            break

        # Source and destination IP addresses
        source_list.append(packet.src)
        destination_list.append(packet.dst)

        # Calculate the relative time of each packet
        relative_time = calculate_package_time_difference(packet, first_packet)
        # chronology_list.append([relative_time, index])
        # Clear reduntant data
        if index < 1:
            chronology_list.append([0, index])
        if not any(relative_time == sublist[0] for sublist in chronology_list):
            chronology_list.append([relative_time, index])

        # Filter OPC UA packets
        if is_opcua_packet(packet, OPCUA_PORTS):
            opcua_packets_index.append(index)

        # TODO: Add an exception here
        # Detect the attack
        if (
            detect_opcua_attack(packet, SERVER_IP, CLIENTS_IPS)
            and 'Packet index' not in attack
        ):
            attack['Relative time'] = relative_time
            attack['Packet index'] = index

    # Calculate the throughput in kbps
    period = chronology_list[-1][0]
    throughput_kbps = calculate_throughput_in_kbps(
        capture, chronology_list, period
    )
    seconds = list(range(1, len(throughput_kbps) + 1))

    print(attack)


if __name__ == '__main__':
    main()
