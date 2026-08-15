#!/usr/bin/env python3
"""
Advanced PCAP Analyzer - Main Entry Point

A professional-grade PCAP/PCAPNG analysis application for network engineers,
NOC engineers, SREs, and security analysts.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from cli import app

if __name__ == "__main__":
    app()
