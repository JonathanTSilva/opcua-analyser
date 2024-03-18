import pyshark


def open_pcapng_file(file_path: str) -> pyshark.FileCapture:
    """Open a PCAPNG file.

    Args:
        file_path: The PCAPNG file to open.

    Returns:
        capture: The PCAPNG file opened.

    Examples:
        >>> open_pcapng_file('')
        Traceback (most recent call last):
        ...
        FileNotFoundError: No such file or directory.
    """
    if file_path == None:
        raise FileNotFoundError('No such file or directory: None')
    elif file_path == '':
        raise FileNotFoundError('No such file or directory.')
    else:
        capture = pyshark.FileCapture(file_path, keep_packets=False)
    #     # for packet in capture:
    #     #     print(packet)
    #     # return capture
    #     return pyshark.FileCapture(file_path, keep_packets=False)


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
