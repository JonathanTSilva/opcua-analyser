"""
Paths and directories initialization
"""

import os
import tempfile

__all__ = [
    'UANALYSER',
    'TEMP',
    'ROOT',
    'LOG',
    'DATA_PCAPNG',
    'DATA_PERF',
    'TESTS',
    'TESTS_ASSETS',
    'DOCS',
    'DOCS_ASSETS',
]

UANALYSER = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(UANALYSER)
TEMP = tempfile.gettempdir()
LOG = os.path.join(UANALYSER, 'uanalyser.log')
DATA_PCAPNG = os.path.join(ROOT, 'Data/network_traffic/no_filter')
DATA_PERF = os.path.join(ROOT, 'Data/get_performance')
TESTS = os.path.join(ROOT, 'tests')
TESTS_ASSETS = os.path.join(TESTS, 'assets')
DOCS = os.path.join(ROOT, 'docs')
DOCS_ASSETS = os.path.join(DOCS, 'assets')
