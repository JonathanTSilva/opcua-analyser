from rich import print
from rich.console import Console
from rich.table import Table
from typer import Argument, run

from uanalyser.preprocessing.file_handling import extract_attack_name

console = Console()


def analyse_package():
    table = Table(title='Extract attack name')
    print(extract_attack_name('path/0-normal_traffic.pcapng'))


if __name__ == '__main__':
    run(analyse_package)
