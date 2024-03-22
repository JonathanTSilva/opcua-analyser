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
    'TESTS',
    'TESTS_ASSETS',
    'DOCS',
    'DOCS_ASSETS',
]

UANALYSER = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(UANALYSER)
TEMP = tempfile.gettempdir()
LOG = os.path.join(UANALYSER, 'uanalyser.log')
TESTS = os.path.join(ROOT, 'tests')
TESTS_ASSETS = os.path.join(TESTS, 'assets')
DOCS = os.path.join(ROOT, 'docs')
DOCS_ASSETS = os.path.join(DOCS, 'assets')
