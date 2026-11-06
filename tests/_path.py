"""Makes src/ importable from the tests (run from the package root:
python -m unittest discover -s tests -v)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src')
FIXTURES = os.path.join(ROOT, 'tests', 'fixtures')

if SRC not in sys.path:
    sys.path.insert(0, SRC)
