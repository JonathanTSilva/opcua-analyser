from preprocessing.file_handling import *
from preprocessing.operations import *


def main():
    capture = open_pcapng_file('tests/assets/example.pcapng')
    chronology_list = []
    attack = []
    for i in range(1, 10):
        chronology_list.append(
            # !TODO Add an exception here
            calculate_package_time_difference(capture[i], capture[0])
        )
    print(chronology_list)


if __name__ == '__main__':
    main()
