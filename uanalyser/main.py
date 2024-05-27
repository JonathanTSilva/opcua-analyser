import scapy.all as scapy
from paths import *
from plot.graphics import *
from preprocessing.file_handling import *
from preprocessing.operations import *

SERVER_IP = '192.168.164.101'
CLIENTS_IPS = ['192.168.164.102']
OPCUA_PORTS = [4840]
# PCAPNG = f'{TESTS_ASSETS}/0-dos_attack_example.pcapng'
PCAPNG = f'{DATA_PCAPNG}/0-dos_function_call_null_deref.pcapng'
# PCAPNG = f'{DATA_PCAPNG}/1-dos_hping3.pcapng'
# PCAPNG = f'{DATA_PCAPNG}/2-mitm_arp.pcapng'


def main():
    # Local variables
    chronology_packets = []

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

    # Plot the Throughput graph
    plot_throughput(throughput_kbps, seconds, attack, performance=False)

    # Calculate the cycle time
    rtts_client_server = calculate_round_trip_time(chronology_packets, 'C-S')
    rtts_attacker_server = calculate_round_trip_time(chronology_packets, 'A-S')
    plot_round_trip_time_per_packet(
        rtts_client_server,
        number_of_packets,
        attack,
        attacker_rtts=rtts_attacker_server,
        performance=True,
    )
    plot_round_trip_time_per_second(
        rtts_client_server,
        seconds,
        attack,
        attacker_rtts=rtts_attacker_server,
        performance=True,
    )
    plot_performance_data(seconds, attack, is_twiny=False)
    plt.show()


if __name__ == '__main__':
    main()
