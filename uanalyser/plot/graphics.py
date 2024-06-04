import re

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter
from paths import *


class GraphUtils:
    """Class to provide utility methods for the graphics."""

    def __init__(self):
        pass

    @staticmethod
    def decode_attack_to_file_name(attack: dict) -> str:
        """Decode the attack to a file name.

        Args:
            attack (dict): The dictionary of the attack.

        Returns:
            str: The file name.

        Example:
            >>> GraphUtils.decode_attack_to_file_name({'Type': 'None', 'Name': 'DOS ATTACK EXAMPLE', 'Relative time': 32.341966, 'Packet index': 1966})
            '0-dos_attack_example'
        """
        type_mapping = {'None': '0', 'Sign': '1', 'Sign & Encrypt': '2'}
        attack_type = type_mapping.get(attack['Type'], 'unknown')
        attack_name = re.sub(r'\s+', '_', attack['Name'].lower())
        return f'{attack_type}-{attack_name}'

    @staticmethod
    def get_csv_data(file_path: str) -> pd.DataFrame:
        """Read the CSV file and return its contents as a DataFrame.

        Args:
            file_path (str): The path to the CSV file.

        Returns:
            pd.DataFrame: The data from the CSV file.

        Raises:
            FileNotFoundError: If the file does not exist.
            Exception: If another unknown error occurs while reading the file.

        Example:
            >>> GraphUtils.get_csv_data('tests/assets/example.csv')
            Traceback (most recent call last):
            ...
            FileNotFoundError: No such file or directory: "tests/assets/example.csv".

            >>> GraphUtils.get_csv_data('tests/assets/0-dos_attack_example.csv')  # doctest: +NORMALIZE_WHITESPACE
                 Timestamp    CPU (%)   Memory (%)
            0     0.000006     5.77        3.75
            ...
            [502 rows x 3 columns]
        """
        try:
            return pd.read_csv(file_path)
        except FileNotFoundError:
            raise FileNotFoundError(
                f'No such file or directory: "{file_path}".'
            )
        except Exception as e:
            raise Exception(f'An error occurred: {e}')

    @staticmethod
    def extract_rtt_plot_values(data: list) -> tuple:
        """Extract the values to plot the round trip time in two different cases:
            - The round trip time values are in the format [index, relative_time, rtt].
            - The round trip time values are in the format [time, rtt].

        Args:
            data (list): The list of round trip times.

        Returns:
            tuple: The tuple of index and rtt values or time and rtt values.

        Raises:
            ValueError: If the data format is invalid.

        Example:
            >>> GraphUtils.extract_rtt_plot_values([[16, 20.80455, 3.999999999848569e-05], [102, 21.089922, 0.002322000000003044], [486, 22.965286, 0.0019799999999996487], [872, 24.852685, 0.001992000000001326], [1034, 25.657321, 0.00211699999999837]])  # doctest: +NORMALIZE_WHITESPACE
            ((16, 102, 486, 872, 1034), (3.999999999848569e-05, 0.002322000000003044, 0.0019799999999996487, 0.001992000000001326, 0.00211699999999837))

            >>> GraphUtils.extract_rtt_plot_values([[20.80455, 3.999999999848569e-05], [21.089922, 0.002322000000003044], [22.965286, 0.0019799999999996487], [24.852685, 0.001992000000001326], [25.657321, 0.00211699999999837]])  # doctest: +NORMALIZE_WHITESPACE
            ((20.80455, 21.089922, 22.965286, 24.852685, 25.657321), (3.999999999848569e-05, 0.002322000000003044, 0.0019799999999996487, 0.001992000000001326, 0.00211699999999837))
        """
        try:
            if len(data[0]) == 3:
                index, rtt = zip(*[(index, rtt) for index, _, rtt in data])
                return index, rtt
            elif len(data[0]) == 2:
                time, rtt = zip(*[(time, rtt) for time, rtt in data])
                return time, rtt
            else:
                raise ValueError(
                    'Invalid data format: Each entry must have 2 or 3 elements.'
                )
        except Exception as e:
            raise ValueError(
                f'An error occurred while extracting RTT plot values: {e}'
            )

    @staticmethod
    def normalize_values(values: list) -> list:
        """Unity-based normalization the values by feature scaling. This is used to bring all values into the range [0,1].

        Args:
            values (list): The list of values.

        Returns:
            list: The list of normalized values.

        Example:
            >>> GraphUtils.normalize_values([0.099609375, 0.099609375, 0.099609375, 0.333984375, 0.0, 13.7861328125])
            [0.007225331161011547, 0.007225331161011547, 0.007225331161011547, 0.024226110363391656, 0.0, 1.0]
        """
        max_value = max(values) if values else 1
        min_value = min(values) if values else 0

        # Check if all values are the same to avoid division by zero
        if min_value == max_value:
            return [0.5] * len(
                values
            )  # Assign a neutral normalized value (e.g., 0.5)

        return [
            (value - min_value) / (max_value - min_value) for value in values
        ]


def performance_data_axle(
    ax: plt.Axes, filename: str, performance: bool, *, twin: bool = True
) -> plt.Axes:
    """Plot performance data alongside the main graph.

    Args:
        ax (matplotlib.axes.Axes): The main axis object.
        filename (str): The name of the file.
        performance (bool): Flag indicating whether performance data should be plotted.
        twin (bool): Flag indicating whether the performance data should be plotted on the same axis.

    Returns:
        matplotlib.axes.Axes: The modified axis object.

    Example:
        >>> import matplotlib.pyplot as plt
        >>> from plot.graphics import GraphUtils
        >>> ax = plt.gca()
        >>> performance_data_axle(ax, '0-dos_function_call_null_deref', performance=True, twin=True)  # doctest: +ELLIPSIS
        <Axes: >
    """
    if performance:
        csv_file = f'{DATA_PERF}/{filename}.csv'
        try:
            performance_data = GraphUtils.get_csv_data(csv_file)

            if set(['Timestamp', 'CPU (%)', 'Memory (%)']).issubset(
                performance_data.columns
            ):
                aux = ax.twinx() if twin else ax
                aux.plot(
                    performance_data['Timestamp'],
                    performance_data['CPU (%)'],
                    color='#90BE6D',
                    linestyle='-',
                    label='CPU',
                )
                aux.plot(
                    performance_data['Timestamp'],
                    performance_data['Memory (%)'],
                    color='#277DA1',
                    linestyle='-',
                    label='RAM',
                )
                aux.set_ylabel('Performance (%)', fontsize=9)
                aux.legend(loc='upper left', fontsize=9)
            else:
                print(
                    f'Performance data in {csv_file} is missing required columns.'
                )
        except FileNotFoundError:
            raise FileNotFoundError(f'File {csv_file} not found.')
        except Exception as e:
            raise Exception(
                f'An error occurred while reading the file {csv_file}: {e}'
            )
    return ax


def plot_performance_data(
    seconds: list,
    attack: dict,
    filename: str,
    *,
    is_twiny: bool = True,
    show_plots: bool = False,
) -> None:
    """Plot performance data.

    Args:
        seconds (list): The list of seconds.
        attack (dict): The dictionary of the attack.
        filename (str): The name of the file.
        is_twiny (bool): Flag indicating whether the performance data should be plotted on the same axis.
        show_plots (bool): Flag indicating whether the plot should be shown.

    Returns:
        None

    Example:
        >>> plot_performance_data([1, 2, 3, 4, 5, 6], {'Type': 'None', 'Name': 'DOS ATTACK EXAMPLE', 'Relative time': 32.341966, 'Packet index': 1966})  # doctest: +SKIP
    """
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.plot(seconds, [0] * len(seconds), color='w', linewidth=0.5)
    if 'Relative time' in attack and attack['Relative time']:
        ax1.axvline(
            x=attack['Relative time'],
            color='#F94144',
            linestyle='--',
            linewidth=0.8,
            label='Início do Ataque',
        )
    ax1.set_xlabel('Tempo (s)', fontsize=9)
    ax1.set_ylabel('Performance (%)', fontsize=9)
    ax1.set_title(
        r'$\bf{DESEMPENHO\;DO\;HOST\;(SERVIDOR)}$'
        + '\n\n'
        + r'$\bf{Nome\;do\;ataque:}$'
        + f'{attack["Name"]} - '
        + r'$\bf{Modo\;de\;segurança:}$'
        + f'{attack["Type"]}',
        fontsize=9,
    )

    ax1.grid(True, linestyle='dotted')
    ax1 = performance_data_axle(ax1, filename, performance=True, twin=is_twiny)
    fig.savefig(
        f'{OUTPUT}/{filename}-perf.png',
        dpi=600,
    )
    if show_plots:
        plt.show(block=False)
    else:
        plt.close(fig)


def plot_throughput(
    throughput_kbps: list,
    seconds: list,
    attack: dict,
    filename: str,
    performance: bool = False,
    show_plots: bool = False,
) -> None:
    """Plot the throughput in kbps.

    Args:
        throughput_kbps (list): The throughput values in kbps.
        seconds (list): The list of seconds.
        attack (dict): The dictionary of the attack.
        filename (str): The name of the file.
        performance (bool): Flag indicating whether performance data should be plotted.
        show_plots (bool): Flag indicating whether the plot should be shown.

    Returns:
        None

    Example:
        >>> plot_throughput([0.099609375, 0.099609375, 0.099609375, 0.333984375, 0.0, 13.7861328125,], [1, 2, 3, 4, 5, 6], {'Type': 'None', 'Name': 'DOS ATTACK EXAMPLE', 'Relative time': 32.341966, 'Packet index': 1966}, '0-dos_function_call_null_deref')  # doctest: +SKIP
    """
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.plot(
        seconds,
        throughput_kbps,
        marker='o',
        color='#277DA1',
        linewidth=0.5,
        markersize=6,
        alpha=0.5,
        label='Throughput (KBps)',
    )
    if 'Relative time' in attack and attack['Relative time']:
        ax1.axvline(
            x=attack['Relative time'],
            color='#F94144',
            linestyle='--',
            linewidth=0.8,
            label='Início do Ataque',
        )
    ax1.set_xlabel('Tempo (s)', fontsize=9)
    ax1.set_ylabel('Throughput (KBps)', fontsize=9)
    ax1.set_title(
        r'$\bf{Throughput}$'
        + '\n\n'
        + r'$\bf{Nome\;do\;ataque:}$'
        + f'{attack["Name"]} - '
        + r'$\bf{Modo\;de\;segurança:}$'
        + f'{attack["Type"]}',
        fontsize=9,
    )
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(True, linestyle='dotted')
    ax1 = performance_data_axle(ax1, filename, performance)
    # plt.subplots_adjust(bottom=0.17)
    # plt.show(block=False)
    fig.savefig(
        f'{OUTPUT}/{filename}-tput.png',
        dpi=600,
    )
    if show_plots:
        plt.show(block=False)
    else:
        plt.close(fig)


def plot_round_trip_time_per_packet(
    rtts: list,
    number_of_packets: int,
    attack: dict,
    filename: str,
    *,
    scale_factor: float = 300.0,
    attacker_rtts: list = None,
    performance: bool = False,
    show_plots: bool = False,
) -> None:
    """Plot the round trip time.

    Args:
        rtts (list): The list of round trip times of a Client-Server communication.
        number_of_packets (int): The number of packets.
        attack (dict): The dictionary of the attack.
        filename (str): The name of the file.
        scale_factor (float): The scale factor.
        attacker_rtts (list): The list of attacker round trip times.
        performance (bool): Flag indicating whether performance data should be plotted.
        show_plots (bool): Flag indicating whether the plot should be shown.

    Returns:
        None

    Example:
        >>> plot_round_trip_time_per_packet([[16, 20.80455, 3.999999999848569e-05], [102, 21.089922, 0.002322000000003044], [486, 22.965286, 0.0019799999999996487], [872, 24.852685, 0.001992000000001326], [1034, 25.657321, 0.00211699999999837]], 3800, {'Type': 'None', 'Name': 'DOS ATTACK EXAMPLE', 'Relative time': 32.341966, 'Packet index': 1966}, scale_factor=300, attacker_rtts=[[2279, 31.794286, 0.00032099999999957163], [2691, 31.851725, 4.4999999996520046e-05], [3051, 35.238601, 0.00015900000000357295], [3094, 35.267045, 5.600000000072214e-05], [3227, 35.275005, 2.9999999995311555e-06]])  # doctest: +SKIP
    """
    x_values, y_values = GraphUtils.extract_rtt_plot_values(rtts)
    normalized_y_values = GraphUtils.normalize_values(y_values)

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.scatter(
        x_values,
        normalized_y_values,
        color='#43AA8B',
        alpha=0.3,
        s=[value * scale_factor for value in normalized_y_values],
        edgecolors='#4D908E',
        linewidths=1,
        label='RTT Cliente-Servidor',
    )

    if attacker_rtts:
        (
            attacker_x_values,
            attacker_y_values,
        ) = GraphUtils.extract_rtt_plot_values(attacker_rtts)
        normalized_attacker_y_values = GraphUtils.normalize_values(
            attacker_y_values
        )
        ax1.scatter(
            attacker_x_values,
            normalized_attacker_y_values,
            color='#F8961E',
            alpha=0.3,
            s=[value * scale_factor for value in normalized_attacker_y_values],
            edgecolors='#F3722C',
            linewidths=1,
            label='RTT Invasor-Servidor',
        )

    if 'Packet index' in attack and attack['Packet index']:
        ax1.axvline(
            x=attack['Packet index'],
            color='#F94144',
            linestyle='--',
            linewidth=0.8,
            label='Início do Ataque',
        )

    ax1.set_xlim(0, number_of_packets - 1)
    ax1.set_yscale('log')

    def log_formatter(x, pos):
        return f'{x:.3f}'

    ax1.yaxis.set_major_formatter(FuncFormatter(log_formatter))

    ax1.grid(True, linestyle='--', alpha=0.7)
    ax1.set_xlabel('Pacote', fontsize=9)
    ax1.set_ylabel('Round Trip Time', fontsize=9)
    ax1.set_title(
        r'$\bf{ROUND\;TRIP\;TIME\;(PACOTE)}$'
        + '\n\n'
        + r'$\bf{Nome\;do\;ataque:}$'
        + f'{attack["Name"]} - '
        + r'$\bf{Modo\;de\;segurança:}$'
        + f'{attack["Type"]}',
        fontsize=9,
    )

    ax1.legend(
        bbox_to_anchor=(0.5, -0.2), fontsize=9, loc='lower center', ncol=3
    )
    # ax1.grid(True, linestyle='dotted')
    plt.subplots_adjust(bottom=0.17)
    fig.savefig(
        f'{OUTPUT}/{filename}-rttp.png',
        dpi=600,
    )
    if show_plots:
        plt.show(block=False)
    else:
        plt.close(fig)


def plot_round_trip_time_per_second(
    rtts: list,
    seconds: list,
    attack: dict,
    filename: str,
    *,
    scale_factor: float = 200.0,
    attacker_rtts: list = None,
    performance: bool = False,
    show_plots: bool = False,
) -> None:
    """Plot the round trip time.

    Args:
        rtts (list): The list of round trip times of a Client-Server communication.
        seconds (list): The list of seconds.
        attack (dict): The dictionary of the attack.
        filename (str): The name of the file.
        scale_factor (float): The scale factor.
        attacker_rtts (list): The list of attacker round trip times.
        performance (bool): Flag indicating whether performance data should be plotted.
        show_plots (bool): Flag indicating whether the plot should be shown.

    Returns:
        None

    Example:
        >>> plot_round_trip_time_per_second([[16, 20.80455, 3.999999999848569e-05], [102, 21.089922, 0.002322000000003044], [486, 22.965286, 0.0019799999999996487], [872, 24.852685, 0.001992000000001326], [1034, 25.657321, 0.00211699999999837]], [1, 2, 3, 4, 5, 6], {'Type': 'None', 'Name': 'DOS ATTACK EXAMPLE', 'Relative time': 32.341966, 'Packet index': 1966}, scale_factor=300, attacker_rtts=[[2279, 31.794286, 0.00032099999999957163], [2691, 31.851725, 4.4999999996520046e-05], [3051, 35.238601, 0.00015900000000357295], [3094, 35.267045, 5.600000000072214e-05], [3227, 35.275005, 2.9999999995311555e-06]])  # doctest: +SKIP
    """

    def group_rtts_by_second(rtts):
        rtts_by_second = {}
        for _, relative_time, rtt in rtts:
            second = int(relative_time)
            if second not in rtts_by_second:
                rtts_by_second[second] = []
            rtts_by_second[second].append(rtt)
        return rtts_by_second

    def calculate_avg_rtts_per_second(rtts_by_second):
        return [
            (second, np.mean(rtts))
            for second, rtts in sorted(rtts_by_second.items())
        ]

    rtts_by_second = group_rtts_by_second(rtts)
    avg_rtts_per_second = calculate_avg_rtts_per_second(rtts_by_second)
    x_values, y_values = GraphUtils.extract_rtt_plot_values(
        avg_rtts_per_second
    )
    normalized_y_values = GraphUtils.normalize_values(y_values)

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.scatter(
        x_values,
        normalized_y_values,
        color='#43AA8B',
        alpha=0.3,
        s=[value * scale_factor for value in normalized_y_values],
        edgecolors='#4D908E',
        linewidths=1,
        label='RTT Cliente-Servidor',
    )

    if attacker_rtts:
        attacker_rtts_by_second = group_rtts_by_second(attacker_rtts)
        avg_attacker_rtts_per_second = calculate_avg_rtts_per_second(
            attacker_rtts_by_second
        )
        (
            attacker_x_values,
            attacker_y_values,
        ) = GraphUtils.extract_rtt_plot_values(avg_attacker_rtts_per_second)
        attacker_normalized_y_values = GraphUtils.normalize_values(
            attacker_y_values
        )

        ax1.scatter(
            attacker_x_values,
            attacker_normalized_y_values,
            color='#F8961E',
            alpha=0.3,
            s=[value * scale_factor for value in attacker_normalized_y_values],
            edgecolors='#F3722C',
            linewidths=1,
            label='RTT Invasor-Servidor',
        )

    if 'Relative time' in attack and attack['Relative time']:
        ax1.axvline(
            x=int(attack['Relative time']),
            color='#F94144',
            linestyle='--',
            linewidth=0.8,
            label='Início do Ataque',
        )

    ax1.set_xlim(0, len(seconds) + 2)
    ax1.set_yscale('log')

    def log_formatter(x, pos):
        return f'{x:.3f}'

    ax1.yaxis.set_major_formatter(FuncFormatter(log_formatter))
    ax1.grid(True, linestyle='--', alpha=0.7)
    ax1.set_xlabel('Tempo (s)', fontsize=9)
    ax1.set_ylabel('Round Trip Time', fontsize=9)
    ax1.set_title(
        r'$\bf{ROUND\;TRIP\;TIME\;(TEMPO)}$'
        + '\n\n'
        + r'$\bf{Nome\;do\;ataque:}$'
        + f'{attack["Name"]} - '
        + r'$\bf{Modo\;de\;segurança:}$'
        + f'{attack["Type"]}',
        fontsize=9,
    )
    ax1.legend(
        bbox_to_anchor=(0.5, -0.2), fontsize=9, loc='lower center', ncol=3
    )
    # plt.grid(True, linestyle='dotted')
    plt.subplots_adjust(bottom=0.17)
    fig.savefig(
        f'{OUTPUT}/{filename}-rtts.png',
        dpi=600,
    )
    if show_plots:
        plt.show(block=False)
    else:
        plt.close(fig)
