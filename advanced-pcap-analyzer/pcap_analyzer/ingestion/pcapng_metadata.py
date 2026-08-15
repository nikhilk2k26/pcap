#!/usr/bin/env python3
"""
PCAPNG Metadata Extractor

Extracts metadata from PCAPNG files including interface information,
capture comments, hardware info, and application details.
"""

import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class InterfaceDescription:
    """Interface description block data."""
    interface_id: int
    link_type: int
    snapshot_length: int
    name: Optional[str] = None
    description: Optional[str] = None
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = None
    eui_address: Optional[str] = None
    speed: Optional[int] = None  # bits per second
    tsoffset: Optional[int] = None  # timestamp offset
    tsoffset_accuracy: Optional[int] = None
    filter: Optional[str] = None
    os: Optional[str] = None
    capture_comments: List[str] = field(default_factory=list)


@dataclass
class SectionInfo:
    """Section header block information."""
    byte_order_magic: int
    major_version: int
    minor_version: int
    section_length: int  # -1 if unknown
    hardware: Optional[str] = None
    os: Optional[str] = None
    user_application: Optional[str] = None
    capture_comments: List[str] = field(default_factory=list)


@dataclass
class PCAPNGMetadata:
    """Complete PCAPNG metadata."""
    sections: List[SectionInfo] = field(default_factory=list)
    interfaces: List[InterfaceDescription] = field(default_factory=list)
    packet_count: int = 0
    file_size: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'sections': [
                {
                    'major_version': s.major_version,
                    'minor_version': s.minor_version,
                    'section_length': s.section_length,
                    'hardware': s.hardware,
                    'os': s.os,
                    'user_application': s.user_application,
                    'capture_comments': s.capture_comments,
                }
                for s in self.sections
            ],
            'interfaces': [
                {
                    'interface_id': i.interface_id,
                    'link_type': i.link_type,
                    'snapshot_length': i.snapshot_length,
                    'name': i.name,
                    'description': i.description,
                    'ipv4_addresses': i.ipv4_addresses,
                    'ipv6_addresses': i.ipv6_addresses,
                    'mac_address': i.mac_address,
                    'speed': i.speed,
                    'filter': i.filter,
                    'os': i.os,
                    'capture_comments': i.capture_comments,
                }
                for i in self.interfaces
            ],
            'packet_count': self.packet_count,
            'file_size': self.file_size,
        }


class PCAPNGMetadataExtractor:
    """
    Extracts metadata from PCAPNG files.
    
    PCAPNG Block Types:
    - 0x0A0D0D0A: Section Header Block (SHB)
    - 0x00000001: Interface Description Block (IDB)
    - 0x00000002: Packet Block (deprecated)
    - 0x00000003: Enhanced Packet Block (EPB)
    - 0x00000004: Simple Packet Block (SPB)
    - 0x00000005: Name Resolution Block (NRB)
    - 0x00000006: Systemd Journal Export Block (SJE)
    - 0x00000007: Decryption Secrets Block (DSB)
    - 0x00000008: Custom Block
    """
    
    # Block types
    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    EPB = 0x00000003
    SPB = 0x00000004
    NRB = 0x00000005
    
    # Option types for IDB
    OPT_ENDOFOPT = 0
    OPT_IF_NAME = 2
    OPT_IF_DESCRIPTION = 3
    OPT_IF_IPV4_ADDR = 4
    OPT_IF_IPV6_ADDR = 5
    OPT_IF_MAC_ADDR = 6
    OPT_IF_EUI_ADDR = 7
    OPT_IF_SPEED = 8
    OPT_IF_TS_OFFSET = 9
    OPT_IF_FILTER = 11
    OPT_IF_OS = 12
    OPT_IF_TSOFFSET_ACCURACY = 14
    
    # Option types for SHB
    OPT_SHB_HARDWARE = 2
    OPT_SHB_OS = 3
    OPT_SHB_USERAPPL = 4
    OPT_SHB_COMMENT = 1
    
    def __init__(self):
        self.current_section: Optional[SectionInfo] = None
        self.interfaces: List[InterfaceDescription] = []
        self.sections: List[SectionInfo] = []
    
    def extract(self, file_path: Path) -> PCAPNGMetadata:
        """
        Extract metadata from a PCAPNG file.
        
        Args:
            file_path: Path to the PCAPNG file
            
        Returns:
            PCAPNGMetadata object with extracted information
        """
        self.sections = []
        self.interfaces = []
        packet_count = 0
        
        try:
            with open(file_path, 'rb') as f:
                file_size = file_path.stat().st_size
                
                while True:
                    block_header = f.read(8)
                    if len(block_header) < 8:
                        break
                    
                    block_type, total_length = struct.unpack('<II', block_header)
                    
                    if block_type == self.SHB:
                        self._parse_shb(f, total_length)
                    elif block_type == self.IDB:
                        self._parse_idb(f, total_length)
                    elif block_type in (self.EPB, self.SPB):
                        packet_count += 1
                        f.seek(total_length - 8, 1)  # Skip packet data
                    else:
                        # Skip unknown blocks
                        f.seek(total_length - 8, 1)
                
                metadata = PCAPNGMetadata(
                    sections=self.sections,
                    interfaces=self.interfaces,
                    packet_count=packet_count,
                    file_size=file_size
                )
                
                return metadata
                
        except Exception as e:
            # Return partial metadata on error
            return PCAPNGMetadata(
                sections=self.sections,
                interfaces=self.interfaces,
                packet_count=packet_count,
                file_size=file_path.stat().st_size if file_path.exists() else 0
            )
    
    def _parse_shb(self, f, total_length: int):
        """Parse Section Header Block."""
        data = f.read(total_length - 12)  # Subtract header + length fields
        
        if len(data) < 12:
            return
        
        # Parse fixed part
        byte_order_magic = struct.unpack('<I', data[0:4])[0]
        version_major = struct.unpack('<H', data[4:6])[0]
        version_minor = struct.unpack('<H', data[6:8])[0]
        section_length = struct.unpack('<Q', data[8:16])[0]
        
        section = SectionInfo(
            byte_order_magic=byte_order_magic,
            major_version=version_major,
            minor_version=version_minor,
            section_length=section_length if section_length != 0xFFFFFFFFFFFFFFFF else -1
        )
        
        # Parse options (start at offset 16)
        self._parse_shb_options(data[16:], section)
        
        self.sections.append(section)
        self.current_section = section
    
    def _parse_shb_options(self, data: bytes, section: SectionInfo):
        """Parse SHB options."""
        offset = 0
        while offset + 4 <= len(data):
            option_type, option_len = struct.unpack('<HH', data[offset:offset+4])
            offset += 4
            
            if option_type == self.OPT_ENDOFOPT:
                break
            
            if offset + option_len > len(data):
                break
            
            option_value = data[offset:offset + option_len]
            offset += option_len
            
            # Align to 32-bit boundary
            while offset % 4 != 0:
                offset += 1
            
            if option_type == self.OPT_SHB_HARDWARE:
                section.hardware = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_SHB_OS:
                section.os = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_SHB_USERAPPL:
                section.user_application = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_SHB_COMMENT:
                section.capture_comments.append(option_value.decode('utf-8', errors='replace'))
    
    def _parse_idb(self, f, total_length: int):
        """Parse Interface Description Block."""
        data = f.read(total_length - 12)
        
        if len(data) < 20:
            return
        
        # Parse fixed part
        link_type = struct.unpack('<H', data[0:2])[0]
        reserved = struct.unpack('<H', data[2:4])[0]
        snaplen = struct.unpack('<I', data[4:8])[0]
        
        iface = InterfaceDescription(
            interface_id=len(self.interfaces),
            link_type=link_type,
            snapshot_length=snaplen
        )
        
        # Parse options (start at offset 20)
        self._parse_idb_options(data[20:], iface)
        
        self.interfaces.append(iface)
        return iface
    
    def _parse_idb_options(self, data: bytes, iface: InterfaceDescription):
        """Parse IDB options."""
        offset = 0
        while offset + 4 <= len(data):
            option_type, option_len = struct.unpack('<HH', data[offset:offset+4])
            offset += 4
            
            if option_type == self.OPT_ENDOFOPT:
                break
            
            if offset + option_len > len(data):
                break
            
            option_value = data[offset:offset + option_len]
            offset += option_len
            
            # Align to 32-bit boundary
            while offset % 4 != 0:
                offset += 1
            
            if option_type == self.OPT_IF_NAME:
                iface.name = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_IF_DESCRIPTION:
                iface.description = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_IF_IPV4_ADDR:
                # Format: 4 bytes IP + 4 bytes netmask + 4 bytes broadcast
                if len(option_value) >= 12:
                    ip = '.'.join(str(b) for b in option_value[0:4])
                    iface.ipv4_addresses.append(ip)
            elif option_type == self.OPT_IF_IPV6_ADDR:
                # Format: 16 bytes IP + 4 bytes prefix + 4 bytes broadcast
                if len(option_value) >= 24:
                    ip = ':'.join(f'{option_value[i*2:(i*2)+2].hex()}' for i in range(8))
                    iface.ipv6_addresses.append(ip)
            elif option_type == self.OPT_IF_MAC_ADDR:
                iface.mac_address = ':'.join(f'{b:02x}' for b in option_value)
            elif option_type == self.OPT_IF_SPEED:
                iface.speed = struct.unpack('<Q', option_value)[0]
            elif option_type == self.OPT_IF_FILTER:
                iface.filter = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_IF_OS:
                iface.os = option_value.decode('utf-8', errors='replace')
            elif option_type == self.OPT_IF_TS_OFFSET:
                iface.tsoffset = struct.unpack('<q', option_value)[0]
    
    def get_interface_summary(self) -> str:
        """Get a human-readable summary of interfaces."""
        lines = []
        for iface in self.interfaces:
            lines.append(f"Interface {iface.interface_id}:")
            if iface.name:
                lines.append(f"  Name: {iface.name}")
            if iface.description:
                lines.append(f"  Description: {iface.description}")
            lines.append(f"  Link Type: {iface.link_type}")
            lines.append(f"  Snapshot Length: {iface.snapshot_length}")
            if iface.mac_address:
                lines.append(f"  MAC: {iface.mac_address}")
            if iface.ipv4_addresses:
                lines.append(f"  IPv4: {', '.join(iface.ipv4_addresses)}")
            if iface.speed:
                lines.append(f"  Speed: {iface.speed} bps")
        return '\n'.join(lines)
