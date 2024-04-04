"""
Provides functions for handling PCAPNG files and extracting information from this.
"""

import scapy.all as scapy


def open_pcapng_file(file_path: str) -> scapy.PacketList:
    """Open a PCAPNG file using scapy.

    Args:
        file_path: The PCAPNG file to open.

    Returns:
        The PCAPNG file opened by scapy package.

    Raises:
        AttributeError: If `file_path` is **None**.
        FileNotFoundError: If the file does not exist.
        ValueError: If `file_path` is an empty string or the if the file has no content.

    Examples:
        >>> open_pcapng_file('tests/assets/example.pcapng')
        <example.pcapng: TCP:6005 UDP:114 ICMP:0 Other:10>

        >>> open_pcapng_file('path/non_existent_example.pcapng')
        Traceback (most recent call last):
        ...
        FileNotFoundError: No such file or directory: "path/non_existent_example.pcapng".

        >>> open_pcapng_file('tests/assets/null_example.pcapng')
        Traceback (most recent call last):
        ...
        ValueError: The file "tests/assets/null_example.pcapng" has no content.

        >>> open_pcapng_file(None)
        Traceback (most recent call last):
        ...
        ValueError: `file_path` must not be None or an empty string.

        >>> open_pcapng_file('')
        Traceback (most recent call last):
        ...
        ValueError: `file_path` must not be None or an empty string.
    """
    if not file_path:
        raise ValueError('`file_path` must not be None or an empty string.')

    try:
        return scapy.rdpcap(file_path)
        # return pyshark.FileCapture(file_path, keep_packets=False)
    except FileNotFoundError:
        raise FileNotFoundError(f'No such file or directory: "{file_path}".')
    except scapy.Scapy_Exception:
        raise ValueError(f'The file "{file_path}" has no content.')


def extract_attack_name(file_path: str) -> dict:
    """Extract the name of the attack from the file name.
    The file name must be in the format `{attack_type}-{attack_name}.pcapng`.
    The attack types are:

        - 0: None
        - 1: Sign
        - 2: Sign & Encrypt

    Args:
        file_path: The file path.

    Returns:
        A dictionary containing the attack type and name.

    Raises:
        ValueError: If the file name format is invalid.

    Examples:
        >>> extract_attack_name('data/pcapng_files/DoS/0-DDoS.pcapng')
        {'Type': 'None', 'Name': 'DDOS'}

        >>> extract_attack_name('data/pcapng_files/DoS/2-MITM_arp_poisoning.pcapng')
        {'Type': 'Sign & Encrypt', 'Name': 'MITM ARP POISONING'}

        >>> extract_attack_name('tests/assets/example.pcapng')
        Traceback (most recent call last):
        ...
        ValueError: Invalid file name format.

        >>> extract_attack_name('tests/assets/3-example.pcapng')
        Traceback (most recent call last):
        ...
        ValueError: Invalid attack type.
    """
    file_parts = file_path.split('/')[-1].split('.')[0].split('-')

    if len(file_parts) < 2:
        raise ValueError('Invalid file name format.')

    attack_type = int(file_parts[0])
    if attack_type == 0:
        attack_type = 'None'
    elif attack_type == 1:
        attack_type = 'Sign'
    elif attack_type == 2:
        attack_type = 'Sign & Encrypt'
    else:
        raise ValueError('Invalid attack type.')

    return {
        'Type': attack_type,
        'Name': file_parts[1].replace('_', ' ').upper(),
    }
