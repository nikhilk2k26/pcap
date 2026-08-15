#!/usr/bin/env python3
"""
Chunk Processor Module

Handles chunked processing of large PCAP files.
Supports streaming, sampling, and progress tracking.
"""

import hashlib
import time
from pathlib import Path
from typing import Iterator, Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field


@dataclass
class ChunkInfo:
    """Information about a processing chunk."""
    chunk_id: int
    start_frame: int
    end_frame: int
    packet_count: int = 0
    byte_count: int = 0
    processing_time_ms: float = 0.0
    status: str = "pending"
    error_message: Optional[str] = None


@dataclass
class ProcessingProgress:
    """Tracks processing progress."""
    total_packets: int = 0
    processed_packets: int = 0
    total_bytes: int = 0
    processed_bytes: int = 0
    start_time: float = field(default_factory=time.time)
    current_chunk: int = 0
    total_chunks: int = 0
    packets_per_second: float = 0.0
    eta_seconds: float = 0.0
    status: str = "pending"
    error_message: Optional[str] = None
    
    @property
    def percent_complete(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return (self.processed_packets / self.total_packets) * 100
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time


class ChunkProcessor:
    """
    Processes large PCAP files in chunks.
    
    Features:
    - Memory-efficient streaming
    - Configurable chunk sizes
    - Progress tracking
    - Sampling support
    - Error recovery
    - Resumable processing
    """
    
    DEFAULT_CHUNK_SIZE = 10000
    DEFAULT_SAMPLE_RATE = 1.0
    
    def __init__(self, 
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 sample_rate: float = DEFAULT_SAMPLE_RATE,
                 max_memory_mb: int = 512,
                 progress_callback: Optional[Callable[[ProcessingProgress], None]] = None):
        self.chunk_size = chunk_size
        self.sample_rate = sample_rate
        self.max_memory_mb = max_memory_mb
        self.progress_callback = progress_callback
        
        self._current_progress = ProcessingProgress()
        self._chunk_history: List[ChunkInfo] = []
    
    def compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of file for deduplication."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def estimate_packet_count(self, file_path: Path) -> int:
        """Estimate total packet count from file size."""
        file_size = file_path.stat().st_size
        avg_packet_size = 500
        return file_size // avg_packet_size
    
    def process_file(self,
                     file_path: Path,
                     packet_processor: Callable[[Dict[str, Any]], Optional[Any]],
                     limit: Optional[int] = None,
                     start_frame: int = 0,
                     analysis_id: Optional[str] = None) -> ProcessingProgress:
        """
        Process a PCAP file in chunks.
        
        Args:
            file_path: Path to PCAP/PCAPNG file
            packet_processor: Function to process each packet
            limit: Maximum packets to process
            start_frame: Starting frame number
            analysis_id: Optional analysis ID for tracking
            
        Returns:
            ProcessingProgress with final statistics
        """
        from ..ingestion.tshark_runner import TSharkRunner
        
        self._current_progress = ProcessingProgress()
        self._current_progress.status = "running"
        self._current_progress.start_time = time.time()
        
        estimated_packets = self.estimate_packet_count(file_path)
        if limit:
            estimated_packets = min(estimated_packets, limit)
        self._current_progress.total_packets = estimated_packets
        
        runner = TSharkRunner()
        
        chunk_id = 0
        current_chunk: List[Dict[str, Any]] = []
        chunk_start_time = time.time()
        
        try:
            packet_stream = runner.stream_packets(
                file_path,
                limit=limit,
                sample_rate=self.sample_rate
            )
            
            for packet in packet_stream:
                frame_number = packet.get('frame_number', 0)
                
                if frame_number < start_frame:
                    continue
                
                if self.sample_rate < 1.0:
                    import random
                    if random.random() > self.sample_rate:
                        continue
                
                current_chunk.append(packet)
                
                frame_length = packet.get('frame_length', 0)
                self._current_progress.processed_bytes += frame_length
                
                if len(current_chunk) >= self.chunk_size:
                    chunk_info = self._process_chunk(
                        chunk_id, current_chunk, packet_processor, chunk_start_time
                    )
                    self._chunk_history.append(chunk_info)
                    
                    self._current_progress.processed_packets += chunk_info.packet_count
                    self._current_progress.current_chunk = chunk_id + 1
                    
                    elapsed = time.time() - self._current_progress.start_time
                    if elapsed > 0:
                        self._current_progress.packets_per_second = (
                            self._current_progress.processed_packets / elapsed
                        )
                        remaining = self._current_progress.total_packets - self._current_progress.processed_packets
                        if self._current_progress.packets_per_second > 0:
                            self._current_progress.eta_seconds = remaining / self._current_progress.packets_per_second
                    
                    if self.progress_callback:
                        self.progress_callback(self._current_progress)
                    
                    current_chunk = []
                    chunk_id += 1
                    chunk_start_time = time.time()
            
            if current_chunk:
                chunk_info = self._process_chunk(
                    chunk_id, current_chunk, packet_processor, chunk_start_time
                )
                self._chunk_history.append(chunk_info)
                self._current_progress.processed_packets += chunk_info.packet_count
                self._current_progress.current_chunk = chunk_id + 1
            
            self._current_progress.status = "completed"
            
        except Exception as e:
            self._current_progress.status = "failed"
            self._current_progress.error_message = str(e)
            raise
        
        return self._current_progress
    
    def _process_chunk(self,
                       chunk_id: int,
                       packets: List[Dict[str, Any]],
                       processor: Callable[[Dict[str, Any]], Optional[Any]],
                       start_time: float) -> ChunkInfo:
        """Process a single chunk of packets."""
        chunk_info = ChunkInfo(
            chunk_id=chunk_id,
            start_frame=packets[0].get('frame_number', 0) if packets else 0,
            end_frame=packets[-1].get('frame_number', 0) if packets else 0,
        )
        
        chunk_info.status = "processing"
        
        try:
            for packet in packets:
                processor(packet)
            
            chunk_info.packet_count = len(packets)
            chunk_info.byte_count = sum(p.get('frame_length', 0) for p in packets)
            chunk_info.processing_time_ms = (time.time() - start_time) * 1000
            chunk_info.status = "completed"
            
        except Exception as e:
            chunk_info.status = "failed"
            chunk_info.error_message = str(e)
        
        return chunk_info
    
    def get_chunk_history(self) -> List[ChunkInfo]:
        """Get history of all processed chunks."""
        return self._chunk_history.copy()
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """Get summary of processing operation."""
        total_processing_time = sum(c.processing_time_ms for c in self._chunk_history)
        successful_chunks = sum(1 for c in self._chunk_history if c.status == "completed")
        failed_chunks = sum(1 for c in self._chunk_history if c.status == "failed")
        
        return {
            "total_packets": self._current_progress.processed_packets,
            "total_bytes": self._current_progress.processed_bytes,
            "total_chunks": len(self._chunk_history),
            "successful_chunks": successful_chunks,
            "failed_chunks": failed_chunks,
            "total_processing_time_ms": total_processing_time,
            "average_chunk_time_ms": (
                total_processing_time / len(self._chunk_history)
                if self._chunk_history else 0
            ),
            "packets_per_second": self._current_progress.packets_per_second,
            "status": self._current_progress.status,
            "error_message": self._current_progress.error_message
        }


def create_progress_bar(total: int, width: int = 40) -> Callable[[int], str]:
    """Create a progress bar formatter."""
    def format_progress(current: int) -> str:
        if total == 0:
            percent = 0
        else:
            percent = (current / total) * 100
        
        filled = int(width * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (width - filled)
        
        return f"[{bar}] {percent:5.1f}% ({current}/{total})"
    
    return format_progress
