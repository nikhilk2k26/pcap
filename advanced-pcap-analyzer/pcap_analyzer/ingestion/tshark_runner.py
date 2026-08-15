#!/usr/bin/env python3
"""
Tshark Runner Module

Executes tshark commands for packet extraction and parsing.
Handles streaming, chunking, and error handling.
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator, Tuple, Generator
from dataclasses import dataclass
import shlex

from config import Config, TsharkConfig


@dataclass
class TsharkResult:
    """Result of a tshark execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    packets_processed: int = 0
    error_message: Optional[str] = None


class TsharkRunner:
    """
    Runs tshark commands for packet extraction.
    
    Supports:
    - JSON output format
    - Field extraction with custom separators
    - Display filters
    - Packet limits
    - Time range filtering
    - Chunked processing for large files
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.tshark_config = self.config.tshark
        self._tshark_path: Optional[str] = None
        self._version: Optional[str] = None
    
    def check_tshark(self) -> bool:
        """Check if tshark is available and working."""
        try:
            result = subprocess.run(
                [self._get_tshark_path(), "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from first line
                lines = result.stdout.strip().split('\n')
                if lines:
                    self._version = lines[0]
                return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _get_tshark_path(self) -> str:
        """Get tshark executable path."""
        if self._tshark_path is None:
            if self.tshark_config.tshark_path:
                self._tshark_path = self.tshark_config.tshark_path
            else:
                # Search in PATH
                import shutil
                tshark = shutil.which("tshark")
                if not tshark:
                    raise RuntimeError(
                        "tshark not found. Please install Wireshark:\n"
                        "  Ubuntu/Debian: sudo apt-get install tshark\n"
                        "  macOS: brew install wireshark\n"
                        "  Windows: https://www.wireshark.org/download.html"
                    )
                self._tshark_path = tshark
        return self._tshark_path
    
    def get_version(self) -> Optional[str]:
        """Get tshark version string."""
        if self._version is None:
            self.check_tshark()
        return self._version
    
    def build_field_args(self) -> List[str]:
        """Build tshark -e field arguments."""
        args = []
        for field in self.tshark_config.default_fields:
            args.extend(["-e", field])
        return args
    
    def run_extraction(
        self,
        file_path: Path,
        display_filter: Optional[str] = None,
        limit: Optional[int] = None,
        sample_rate: float = 1.0,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interface_id: Optional[int] = None,
    ) -> TsharkResult:
        """
        Run tshark to extract packet data.
        
        Args:
            file_path: Path to capture file
            display_filter: tshark display filter
            limit: Maximum number of packets to extract
            sample_rate: Sample rate (1.0 = all packets)
            start_time: Start time filter
            end_time: End time filter
            interface_id: Interface ID to filter
            
        Returns:
            TsharkResult with extracted data
        """
        cmd = [
            self._get_tshark_path(),
            "-r", str(file_path),
            "-T", "fields",
            "-E", f"separator={self.tshark_config.tshark_fields_separator}",
            "-E", "header=y",
            "-E", "quote=d",
        ]
        
        # Add field extraction
        cmd.extend(self.build_field_args())
        
        # Add display filter
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        # Add time range filters
        if start_time:
            cmd.extend(["-R", f"frame.time_epoch >= {start_time}"])
        if end_time:
            cmd.extend(["-R", f"frame.time_epoch <= {end_time}"])
        
        # Add interface filter
        if interface_id is not None:
            cmd.extend(["-i", str(interface_id)])
        
        # Add packet limit
        if limit:
            cmd.extend(["-c", str(limit)])
        
        # Execute
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1024 * 1024,  # 1MB buffer
            )
            
            stdout_lines = []
            packet_count = 0
            
            for line in process.stdout:
                line = line.strip()
                if line:
                    stdout_lines.append(line)
                    packet_count += 1
            
            stderr_output = process.stderr.read()
            return_code = process.wait(timeout=self.config.analysis.tshark_timeout_seconds)
            
            return TsharkResult(
                success=return_code == 0,
                stdout='\n'.join(stdout_lines),
                stderr=stderr_output,
                return_code=return_code,
                packets_processed=packet_count,
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            return TsharkResult(
                success=False,
                error_message=f"tshark timed out after {self.config.analysis.tshark_timeout_seconds}s"
            )
        except Exception as e:
            return TsharkResult(
                success=False,
                error_message=str(e)
            )
    
    def run_json_extraction(
        self,
        file_path: Path,
        display_filter: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> TsharkResult:
        """
        Run tshark with JSON output for detailed packet dissection.
        
        Args:
            file_path: Path to capture file
            display_filter: tshark display filter
            limit: Maximum number of packets
            
        Returns:
            TsharkResult with JSON data
        """
        cmd = [
            self._get_tshark_path(),
            "-r", str(file_path),
            "-T", "ek",  # Elasticsearch-compatible JSON
        ]
        
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        if limit:
            cmd.extend(["-c", str(limit)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.analysis.tshark_timeout_seconds,
            )
            
            # Count packets in JSON output
            packet_count = result.stdout.count('"layers"')
            
            return TsharkResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                packets_processed=packet_count,
            )
            
        except subprocess.TimeoutExpired:
            return TsharkResult(
                success=False,
                error_message=f"tshark timed out after {self.config.analysis.tshark_timeout_seconds}s"
            )
        except Exception as e:
            return TsharkResult(
                success=False,
                error_message=str(e)
            )
    
    def stream_packets(
        self,
        file_path: Path,
        display_filter: Optional[str] = None,
        chunk_size: int = 10000,
    ) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Stream packets in chunks using tshark.
        
        Args:
            file_path: Path to capture file
            display_filter: tshark display filter
            chunk_size: Number of packets per chunk
            
        Yields:
            Lists of packet dictionaries
        """
        cmd = [
            self._get_tshark_path(),
            "-r", str(file_path),
            "-T", "json",
        ]
        
        if display_filter:
            cmd.extend(["-Y", display_filter])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            # Read JSON incrementally
            buffer = ""
            packet_buffer = []
            in_packet = False
            brace_count = 0
            
            while True:
                chunk = process.stdout.read(8192)
                if not chunk:
                    break
                
                buffer += chunk.decode('utf-8', errors='replace')
                
                # Simple JSON packet detection
                i = 0
                while i < len(buffer):
                    char = buffer[i]
                    
                    if char == '{':
                        if not in_packet:
                            in_packet = True
                            current_packet = ""
                        brace_count += 1
                        current_packet += char
                    elif char == '}':
                        current_packet += char
                        brace_count -= 1
                        
                        if brace_count == 0 and in_packet:
                            in_packet = False
                            try:
                                packet = json.loads(current_packet)
                                packet_buffer.append(packet)
                                
                                if len(packet_buffer) >= chunk_size:
                                    yield packet_buffer
                                    packet_buffer = []
                            except json.JSONDecodeError:
                                pass
                            current_packet = ""
                    elif in_packet:
                        current_packet += char
                    
                    i += 1
                
                buffer = buffer[i:] if i < len(buffer) else ""
            
            # Yield remaining packets
            if packet_buffer:
                yield packet_buffer
            
            process.wait()
            
        except Exception as e:
            raise RuntimeError(f"Error streaming packets: {e}")
    
    def get_packet_count(self, file_path: Path) -> int:
        """Get total packet count in a capture file."""
        cmd = [
            self._get_tshark_path(),
            "-r", str(file_path),
            "-T", "fields",
            "-e", "frame.number",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.analysis.tshark_timeout_seconds,
            )
            
            if result.returncode == 0:
                lines = [l for l in result.stdout.strip().split('\n') if l]
                return len(lines)
            return 0
            
        except Exception:
            return 0
    
    def get_capture_info(self, file_path: Path) -> Dict[str, Any]:
        """Get capture file information."""
        cmd = [
            self._get_tshark_path(),
            "-r", str(file_path),
            "-q", "-z", "io,stat,0",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            info = {}
            for line in result.stdout.split('\n'):
                if 'Duration:' in line:
                    info['duration'] = line.split(':')[1].strip()
                elif 'Start time:' in line:
                    info['start_time'] = line.split(':')[1].strip()
                elif 'End time:' in line:
                    info['end_time'] = line.split(':')[1].strip()
            
            return info
            
        except Exception:
            return {}
