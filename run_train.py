"""
run_train.py — Project launcher script.

Run this file from the project root directory to start the full ML training pipeline:

    python run_train.py

This script correctly sets the Python path so that the `src` package
is found regardless of IDE or terminal configuration.
"""

import os
import sys

# Add the project root folder to sys.path so `src` is importable
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from src.train import main

if __name__ == "__main__":
    main()
