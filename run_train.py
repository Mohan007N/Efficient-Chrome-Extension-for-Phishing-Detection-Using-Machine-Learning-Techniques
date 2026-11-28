"""
run_train.py — WebShield AI v3.0 Full Training Pipeline Launcher

Runs both separated, leak-free URL and DOM model selection, calibration,
threshold tuning, untouched test evaluation, and atomic registry promotion:

    python run_train.py
"""

import os
import sys

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from src.train import main as train_url_main
from src.train_dom import main as train_dom_main


def main():
    print("=" * 60)
    print(" WebShield AI v3.0 — URL & DOM Training Pipeline")
    print("=" * 60)
    train_url_main()
    print()
    train_dom_main()


if __name__ == "__main__":
    main()
