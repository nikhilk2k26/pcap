"""
Ingestion Module

Handles PCAP/PCAPNG file detection, metadata extraction, and packet ingestion.
"""

from .file_detector import FileDetector
from .pcapng_metadata import PCAPNGMetadataExtractor
from .tshark_runner import TsharkRunner
from .packet_stream import PacketStream
from .chunk_processor import ChunkProcessor

__all__ = [
    "FileDetector",
    "PCAPNGMetadataExtractor",
    "TsharkRunner",
    "PacketStream",
    "ChunkProcessor",
]
