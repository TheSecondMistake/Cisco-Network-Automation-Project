"""
Path Configuration Utility

This module dynamically resolves the absolute path of the project's root 
directory and inserts it into the system's search path (`sys.path`). This 
allows scripts nested within subordinate folders (like `/scripts`) to cleanly 
import modules from sister directories (like `/utils`).

Usage:
    This module MUST be imported at the very top of any executable script, 
    before any local imports are called:
    
    >>> import paths
    >>> from utils import generic as gutils
"""

import sys
from pathlib import Path

# Navigates up to the root directory (adjust parents[0] or parents[1] based on your depth)
root_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root_dir))
