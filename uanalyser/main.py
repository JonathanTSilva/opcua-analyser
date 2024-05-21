import scapy.all as scapy
from paths import *
from plot.graphics import *
from preprocessing.file_handling import *
from preprocessing.operations import *

SERVER_IP = '192.168.164.101'
CLIENTS_IPS = ['192.168.164.102']
OPCUA_PORTS = [4840]
PCAPNG = f'{TESTS_ASSETS}/0-dos_attack_example.pcapng'
# PCAPNG = f'{DATA}/0-dos_function_call_null_deref.pcapng'


def main():
    # Local variables
    chronology_list = []
    comm_description = []
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

        # Calculate the relative time of each packet
        relative_time = calculate_package_time_difference(packet, first_packet)

        # Define the type of the package: request or response
        comm_type = define_communication_type(packet, SERVER_IP, CLIENTS_IPS)

        # Clear reduntant data
        if index < 1:
            chronology_list.append([index, 0])
            comm_description.append([index, packet.src, packet.dst, comm_type])
        if not any(relative_time == sublist[1] for sublist in chronology_list):
            chronology_list.append([index, relative_time])
            comm_description.append([index, packet.src, packet.dst, comm_type])

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
    period = chronology_list[-1][1]
    throughput_kbps = calculate_throughput_in_kbps(
        capture, chronology_list, period
    )
    seconds = list(range(1, len(throughput_kbps) + 1))

    # print('Attack: ', attack)
    # print('throughput_kbps: ',throughput_kbps)
    # print('Seconds: ',seconds)
    # print('chronology_list: ', len(chronology_list))
    # print('opcua_packets_index', opcua_packets_index)
    # print('Communication list: ', comm_description)

    # Plot the Throughput graph
    plot_throughput(throughput_kbps, seconds, attack)

    # Calculate the cycle time
    # rtt = calculate_round_trip_time(capture, addresses, SERVER_IP, CLIENTS_IPS)


if __name__ == '__main__':
    main()
