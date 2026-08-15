#!/usr/bin/env python3
"""
File Detector Module

Detects file type (PCAP vs PCAPNG) and validates capture files.
"""

import struct
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class CaptureFileType(Enum):
    """Supported capture file types."""
    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


@dataclass
class FileDetectionResult:
    """Result of file detection."""
    file_type: CaptureFileType
    is_valid: bool
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class FileDetector:
    """
    Detects and validates PCAP/PCAPNG files.
    
    Uses magic numbers to identify file types:
    - PCAP: 0xa1b2c3d4 or 0xd4c3b2a1
    - PCAPNG: 0x0a0d0d0a
    """
    
    # Magic numbers
    PCAP_MAGIC_LE = 0xa1b2c3d4
    PCAP_MAGIC_BE = 0xd4c3b2a1
    PCAPNG_MAGIC = 0x0a0d0d0a
    
    # Section header block type for PCAPNG
    SHB_BLOCK_TYPE = 0x0A0D0D0A
    
    def __init__(self):
        pass
    
    def detect(self, file_path: Path) -> FileDetectionResult:
        """
        Detect the type of capture file.
        
        Args:
            file_path: Path to the capture file
            
        Returns:
            FileDetectionResult with file type and validation info
        """
        if not file_path.exists():
            return FileDetectionResult(
                file_type=CaptureFileType.UNKNOWN,
                is_valid=False,
                error_message=f"File not found: {file_path}"
            )
        
        if not file_path.is_file():
            return FileDetectionResult(
                file_type=CaptureFileType.UNKNOWN,
                is_valid=False,
                error_message=f"Not a file: {file_path}"
            )
        
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                
            if len(magic_bytes) < 4:
                return FileDetectionResult(
                    file_type=CaptureFileType.UNKNOWN,
                    is_valid=False,
                    error_message="File too small to be a valid capture"
                )
            
            magic = struct.unpack('<I', magic_bytes)[0]
            
            if magic == self.PCAPNG_MAGIC:
                return self._validate_pcapng(file_path)
            elif magic in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_BE):
                return self._validate_pcap(file_path, magic)
            else:
                # Try to detect by extension as fallback
                suffix = file_path.suffix.lower()
                if suffix in ('.pcapng', '.ntar'):
                    return FileDetectionResult(
                        file_type=CaptureFileType.PCAPNG,
                        is_valid=True,
                        metadata={'detected_by': 'extension'}
                    )
                elif suffix in ('.pcap', '.cap'):
                    return FileDetectionResult(
                        file_type=CaptureFileType.PCAP,
                        is_valid=True,
                        metadata={'detected_by': 'extension'}
                    )
                else:
                    return FileDetectionResult(
                        file_type=CaptureFileType.UNKNOWN,
                        is_valid=False,
                        error_message=f"Unknown file format (magic: 0x{magic:08x})"
                    )
                    
        except PermissionError:
            return FileDetectionResult(
                file_type=CaptureFileType.UNKNOWN,
                is_valid=False,
                error_message=f"Permission denied: {file_path}"
            )
        except Exception as e:
            return FileDetectionResult(
                file_type=CaptureFileType.UNKNOWN,
                is_valid=False,
                error_message=f"Error reading file: {e}"
            )
    
    def _validate_pcap(self, file_path: Path, magic: int) -> FileDetectionResult:
        """Validate a PCAP file."""
        try:
            with open(file_path, 'rb') as f:
                # Read global header (24 bytes)
                header = f.read(24)
                
            if len(header) < 24:
                return FileDetectionResult(
                    file_type=CaptureFileType.PCAP,
                    is_valid=False,
                    error_message="PCAP file too small (incomplete header)"
                )
            
            # Parse header
            if magic == self.PCAP_MAGIC_LE:
                version_major, version_minor = struct.unpack('<HH', header[4:8])
                snaplen = struct.unpack('<I', header[16:20])[0]
                linktype = struct.unpack('<I', header[20:24])[0]
            else:
                version_major, version_minor = struct.unpack('>HH', header[4:8])
                snaplen = struct.unpack('>I', header[16:20])[0]
                linktype = struct.unpack('>I', header[20:24])[0]
            
            metadata = {
                'version_major': version_major,
                'version_minor': version_minor,
                'snaplen': snaplen,
                'linktype': linktype,
                'byte_order': 'little' if magic == self.PCAP_MAGIC_LE else 'big'
            }
            
            # Basic validation
            if version_major != 2:
                return FileDetectionResult(
                    file_type=CaptureFileType.PCAP,
                    is_valid=False,
                    error_message=f"Invalid PCAP version: {version_major}.{version_minor}",
                    metadata=metadata
                )
            
            return FileDetectionResult(
                file_type=CaptureFileType.PCAP,
                is_valid=True,
                metadata=metadata
            )
            
        except Exception as e:
            return FileDetectionResult(
                file_type=CaptureFileType.PCAP,
                is_valid=False,
                error_message=f"Error validating PCAP: {e}"
            )
    
    def _validate_pcapng(self, file_path: Path) -> FileDetectionResult:
        """Validate a PCAPNG file."""
        try:
            with open(file_path, 'rb') as f:
                # Read Section Header Block (minimum 28 bytes)
                shb = f.read(28)
                
            if len(shb) < 28:
                return FileDetectionResult(
                    file_type=CaptureFileType.PCAPNG,
                    is_valid=False,
                    error_message="PCAPNG file too small (incomplete SHB)"
                )
            
            # Validate SHB structure
            block_type = struct.unpack('<I', shb[0:4])[0]
            total_length = struct.unpack('<I', shb[4:8])[0]
            
            if block_type != self.SHB_BLOCK_TYPE:
                return FileDetectionResult(
                    file_type=CaptureFileType.PCAPNG,
                    is_valid=False,
                    error_message=f"Invalid PCAPNG SHB block type: 0x{block_type:08x}"
                )
            
            if total_length < 28:
                return FileDetectionResult(
                    file_type=CaptureFileType.PCAPNG,
                    is_valid=False,
                    error_message=f"Invalid PCAPNG SHB length: {total_length}"
                )
            
            # Read version
            version_major = struct.unpack('<H', shb[8:10])[0]
            version_minor = struct.unpack('<H', shb[10:12])[0]
            
            metadata = {
                'version_major': version_major,
                'version_minor': version_minor,
                'section_length': total_length
            }
            
            return FileDetectionResult(
                file_type=CaptureFileType.PCAPNG,
                is_valid=True,
                metadata=metadata
            )
            
        except Exception as e:
            return FileDetectionResult(
                file_type=CaptureFileType.PCAPNG,
                is_valid=False,
                error_message=f"Error validating PCAPNG: {e}"
            )
    
    def get_file_size(self, file_path: Path) -> int:
        """Get file size in bytes."""
        return file_path.stat().st_size
    
    def is_supported(self, file_path: Path) -> bool:
        """Check if file type is supported."""
        result = self.detect(file_path)
        return result.is_valid and result.file_type in (
            CaptureFileType.PCAP,
            CaptureFileType.PCAPNG
        )
