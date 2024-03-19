from uanalyser.preprocessing.file_handling import *


def main():
    capture = open_pcapng_file('tests/assets/example.pcapng')
    for packet in capture:
        print(packet)


if __name__ == '__main__':
    main()
