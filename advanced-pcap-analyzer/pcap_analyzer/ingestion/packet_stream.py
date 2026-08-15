#!/usr/bin/env python3
"""
Packet Stream Module

Handles streaming packet data from tshark output.
"""

from typing import Iterator, List, Dict, Any, Optional
from pathlib import Path


class PacketStream:
    """
    Streams packets from capture files without loading everything into memory.
    """
    
    def __init__(self, file_path: Path, batch_size: int = 1000):
        self.file_path = file_path
        self.batch_size = batch_size
    
    def stream_packets(self) -> Iterator[Dict[str, Any]]:
        """
        Stream packets one at a time.
        
        Yields:
            Packet dictionaries
        """
        # This would be implemented with actual tshark streaming
        # For now, it's a placeholder
        pass
    
    def stream_batches(self) -> Iterator[List[Dict[str, Any]]]:
        """
        Stream packets in batches.
        
        Yields:
            Lists of packet dictionaries
        """
        batch = []
        for packet in self.stream_packets():
            batch.append(packet)
            if len(batch) >= self.batch_size:
                yield batch
                batch = []
        
        if batch:
            yield batch
