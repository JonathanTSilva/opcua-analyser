import pyshark
import scapy.all as scapy


def open_pcapng_file(file_path: str) -> pyshark.FileCapture:
    """Open a PCAPNG file.

    Args:
        file_path: The PCAPNG file to open.

    Returns:
        The PCAPNG file opened.

    Raises:
        AttributeError: If `file_path` is None.
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
        # capture = pyshark.FileCapture(file_path, keep_packets=False)  # <FileCapture>
        return scapy.rdpcap(file_path)
    except FileNotFoundError:
        raise FileNotFoundError(f'No such file or directory: "{file_path}".')
    except scapy.Scapy_Exception:
        raise ValueError(f'The file "{file_path}" has no content.')


def extract_attack_name(file_path: str) -> list:
    """Extract the name of the attack from the file name.

    Args:
        file_path (String): The file path.

    Returns:
        The list containing the attack type [0] and name [1].

    Raises:
        ValueError: If the file name format is invalid.

    Examples:
        >>> extract_attack_name('data/pcapng_files/DoS/0-DDoS.pcapng')
        [0, 'DDoS']

        >>> extract_attack_name('../tests/assets/example.pcapng')
        Traceback (most recent call last):
        ...
        ValueError: Invalid file name format.
    """
    file_parts = file_path.split('/')[-1].split('.')[0].split('-')
    if len(file_parts) < 2:
        raise ValueError('Invalid file name format.')
    return [int(file_parts[0]), file_parts[1]]
