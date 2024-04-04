from pytest import mark, raises

from uanalyser.preprocessing.file_handling import (
    extract_attack_name,
    open_pcapng_file,
)


def test_open_valid_pcapng_file():
    example_file_path = 'tests/assets/example.pcapng'

    result = open_pcapng_file(example_file_path)

    assert result


def test_open_non_existent_pcapng_file():
    non_existent_example_file_path = 'tests/assets/non_existing_file.pcapng'
    error_message = (
        f'No such file or directory: "{non_existent_example_file_path}".'
    )

    with raises(FileNotFoundError) as error:
        open_pcapng_file(non_existent_example_file_path)

    assert error_message == error.value.args[0]  # equals: str(error.value)


def test_open_none_pcapng_file():
    error_message = '`file_path` must not be None or an empty string.'

    with raises(ValueError) as error:
        open_pcapng_file(None)

    assert error_message == error.value.args[0]


def test_open_null_pcapng_file():
    null_exemple_file_path = 'tests/assets/null_example.pcapng'
    error_message = f'The file "{null_exemple_file_path}" has no content.'

    with raises(ValueError) as error:
        open_pcapng_file(null_exemple_file_path)

    assert error_message == error.value.args[0]


@mark.parametrize(
    'file_path, expected',
    [
        (
            'path/0-normal_traffic.pcapng',
            {'Type': 'None', 'Name': 'NORMAL TRAFFIC'},
        ),
        (
            'path/2-attack_traffic.pcapng',
            {'Type': 'Sign & Encrypt', 'Name': 'ATTACK TRAFFIC'},
        ),
        (
            'path/1-dos_function_call_null_deref.pcapng',
            {'Type': 'Sign', 'Name': 'DOS FUNCTION CALL NULL DEREF'},
        ),
    ],
)
def test_extract_valid_attack_name(file_path: str, expected: list[int | str]):
    result = extract_attack_name(file_path)

    assert result == expected


@mark.parametrize(
    'file_path, expected',
    [
        (
            'path/normal_traffic.pcapng',
            'Invalid file name format.',
        ),
        ('path/3-attack_traffic.pcapng', 'Invalid attack type.'),
    ],
)
def test_extract_wrong_attack_name(file_path: str, expected: list[int | str]):

    with raises(ValueError) as error:
        extract_attack_name(file_path)

    assert expected == error.value.args[0]
