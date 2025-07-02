#!/usr/bin/env python3
import sys
import struct
from pathlib import Path
from typing import List, Optional, Tuple, Union

# Type aliases for better readability
ResourceType = Union[int, str]
SectionInfo = Tuple[bytes, int, int, int]  # (name, virtual_address, raw_offset, raw_size)
PEHeaderResult = Tuple[int, int, List[SectionInfo]]  # (resource_rva, resource_size, sections)

RESOURCE_TYPES: dict[int, str] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP", 
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST"
}

def read_pe_header(file_path: str) -> Optional[PEHeaderResult]:
    try:
        with open(file_path, 'rb') as f:
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                return None
            
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)
            
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                return None
            
            coff_header = f.read(20)
            machine, sections_count = struct.unpack('<HH', coff_header[:4])
            
            optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
            optional_header = f.read(optional_header_size)
            
            if len(optional_header) < 96:
                return None
            
            magic = struct.unpack('<H', optional_header[:2])[0]
            is_pe32_plus = magic == 0x20b
            
            if is_pe32_plus:
                data_dir_offset = 112
            else:
                data_dir_offset = 96
            
            if len(optional_header) < data_dir_offset + 8:
                return None
            
            resource_table_rva = struct.unpack('<I', optional_header[data_dir_offset + 16:data_dir_offset + 20])[0]
            resource_table_size = struct.unpack('<I', optional_header[data_dir_offset + 20:data_dir_offset + 24])[0]
            
            if resource_table_rva == 0:
                return None
            
            sections = []
            for _ in range(sections_count):
                section = f.read(40)
                if len(section) < 40:
                    break
                name = section[:8].rstrip(b'\x00')
                virtual_size, virtual_address, raw_size, raw_offset = struct.unpack('<IIII', section[8:24])
                sections.append((name, virtual_address, raw_offset, raw_size))
            
            return resource_table_rva, resource_table_size, sections
    except Exception as e:
        return None

def find_resource_section(sections: List[SectionInfo], rva: int) -> Optional[int]:
    for name, va, offset, size in sections:
        if va <= rva < va + size:
            return offset + (rva - va)
    return None

def parse_resource_string(data: bytes, offset: int) -> Optional[str]:
    if offset + 2 > len(data):
        return None
    
    length = struct.unpack('<H', data[offset:offset+2])[0]
    if offset + 2 + length * 2 > len(data):
        return None
    
    string_data = data[offset+2:offset+2+length*2]
    return string_data.decode('utf-16le', errors='ignore')

def parse_resource_directory(data: bytes, offset: int, level: int = 0) -> List[ResourceType]:
    if offset + 16 > len(data):
        return []
    
    characteristics, timestamp, major_ver, minor_ver, name_entries, id_entries = struct.unpack('<IIHHHH', data[offset:offset+16])
    
    entries = []
    entry_offset = offset + 16
    
    for i in range(name_entries + id_entries):
        if entry_offset + 8 > len(data):
            break
        
        name_id, data_offset = struct.unpack('<II', data[entry_offset:entry_offset+8])
        
        if level == 0:
            if i < name_entries:
                if name_id & 0x80000000:
                    string_offset = name_id & 0x7FFFFFFF
                    resource_name = parse_resource_string(data, string_offset)
                    if resource_name:
                        entries.append(resource_name)
            else:
                entries.append(name_id)
        
        if data_offset & 0x80000000:
            subdir_offset = data_offset & 0x7FFFFFFF
            if level == 0:
                sub_entries = parse_resource_directory(data, subdir_offset, level + 1)
                entries.extend(sub_entries)
        
        entry_offset += 8
    
    return entries

def get_resource_types(file_path: str) -> List[ResourceType]:
    result = read_pe_header(file_path)
    if result is None:
        return []
    
    resource_rva, resource_size, sections = result
    
    resource_offset = find_resource_section(sections, resource_rva)
    if resource_offset is None:
        raise RuntimeError(f"Could not locate resource section in {file_path}")
    
    with open(file_path, 'rb') as f:
        f.seek(resource_offset)
        resource_data = f.read(resource_size)
    
    resource_types = parse_resource_directory(resource_data, 0)
    unique_types = []
    seen = set()
    
    for res_type in resource_types:
        if res_type not in seen:
            unique_types.append(res_type)
            seen.add(res_type)
    
    return sorted(unique_types, key=lambda x: (isinstance(x, str), x))

def list_resources(file_path: str) -> None:
    try:
        resource_types = get_resource_types(file_path)
        
        if not resource_types:
            print(f"No resource types found in {file_path}")
            return
        
        for res_type in resource_types:
            if isinstance(res_type, str):
                print(f'"{res_type}"')
            else:
                type_name = RESOURCE_TYPES.get(res_type, "UNKNOWN")
                print(f"{res_type} ({type_name})")
    
    except ValueError as e:
        print(f"Error: {e}")
    except RuntimeError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error reading resource data: {e}")

def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python list_resources.py <path_to_executable>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not Path(file_path).exists():
        print(f"Error: File {file_path} does not exist")
        sys.exit(1)
    
    list_resources(file_path)

if __name__ == "__main__":
    main()
