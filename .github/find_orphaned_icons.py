#!/usr/bin/env python3
"""
Script to find orphaned icon resources in Windows DLL files.
Identifies icons (RT_ICON) that are not referenced by any icon group (RT_GROUP_ICON).
"""

import os
import sys
import argparse
from pe_tools import parse_pe

def analyze_icon_resources(dll_path, debug=False):
    """Analyze icon and icon group resources in a DLL file."""
    with open(dll_path, 'rb') as f:
        pe = parse_pe(f.read())

    resources = pe.parse_resources()
    if not resources:
        if debug:
            print(f"No resources found in {dll_path}")
        return [], {}

    # RT_ICON = 3, RT_GROUP_ICON = 14
    icons = set()
    icon_groups = {}
    referenced_icons = set()

    # Get all icon resources (RT_ICON = 3)
    if 3 in resources:
        for icon_id in resources[3].keys():
            icons.add(icon_id)
            if debug:
                print(f"  Found icon: {icon_id}")

    # Get all icon group resources (RT_GROUP_ICON = 14) and parse them
    if 14 in resources:
        for group_id, languages in resources[14].items():
            if debug:
                print(f"  Found icon group: {group_id}")

            # Parse the icon group to find referenced icons
            for language_id, group_data in languages.items():
                group_bytes = bytes(group_data)
                referenced_in_group = parse_icon_group(group_bytes, debug, group_id)
                referenced_icons.update(referenced_in_group)
                icon_groups[group_id] = referenced_in_group

    # Find orphaned icons
    orphaned_icons = icons - referenced_icons

    if debug:
        print(f"  Total icons: {len(icons)}")
        print(f"  Total icon groups: {len(icon_groups)}")
        print(f"  Referenced icons: {sorted(referenced_icons)}")
        print(f"  Orphaned icons: {sorted(orphaned_icons)}")

    return list(orphaned_icons), icon_groups

def parse_icon_group(group_data, debug=False, group_id=None):
    """Parse an icon group resource to extract referenced icon IDs."""
    referenced_icons = set()

    if len(group_data) < 6:
        return referenced_icons

    # Icon group header structure:
    # WORD idReserved (must be 0)
    # WORD idType (must be 1 for icons)
    # WORD idCount (number of icon entries)

    import struct
    header = struct.unpack('<HHH', group_data[:6])
    reserved, icon_type, count = header

    if debug and group_id:
        print(f"    Group {group_id}: reserved={reserved}, type={icon_type}, count={count}")

    if icon_type != 1:  # Not an icon group
        return referenced_icons

    # Each icon entry is 14 bytes:
    # BYTE bWidth, BYTE bHeight, BYTE bColorCount, BYTE bReserved
    # WORD wPlanes, WORD wBitCount
    # DWORD dwBytesInRes
    # WORD nID (the icon resource ID we're looking for)

    for i in range(count):
        entry_offset = 6 + (i * 14)
        if entry_offset + 14 <= len(group_data):
            entry_data = group_data[entry_offset:entry_offset + 14]
            entry = struct.unpack('<BBBBHHIH', entry_data)

            width, height, colors, reserved, planes, bit_count, size, icon_id = entry
            referenced_icons.add(icon_id)

            if debug and group_id:
                print(f"      Entry {i}: {width}x{height}, {bit_count}bit, icon_id={icon_id}")

    return referenced_icons

def analyze_dll_file(dll_path, debug=False):
    """Analyze a single DLL file for orphaned icons."""
    print(f"\nAnalyzing: {dll_path}")

    orphaned_icons, icon_groups = analyze_icon_resources(dll_path, debug)

    print(f"Found {len(orphaned_icons)} orphaned icons")

    if debug and icon_groups:
        print(f"Icon groups:")
        for group_id, icons in icon_groups.items():
            print(f"  Group {group_id}: references icons {sorted(icons)}")

    result = []
    for icon_id in sorted(orphaned_icons):
        result.append({
            'file': dll_path,
            'icon_id': icon_id
        })

    return result

def is_supported_file(filename):
    """Check if file has a supported extension (.dll or .exe)."""
    return filename.lower().endswith(('.dll', '.exe'))

def find_pe_files(directory):
    """Find all PE files (DLL and EXE) in directory and subdirectories."""
    pe_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if is_supported_file(file):
                pe_files.append(os.path.join(root, file))
    return pe_files

def main():
    parser = argparse.ArgumentParser(description='Find orphaned icon resources in PE files (DLL and EXE)')
    parser.add_argument('path', help='Path to PE file or directory to scan')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively scan directories for PE files')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug output for each file')

    args = parser.parse_args()

    all_orphaned = []

    if os.path.isfile(args.path):
        # Single file - let analyze_dll_file handle file validation
        all_orphaned.extend(analyze_dll_file(args.path, args.debug))
    elif os.path.isdir(args.path):
        # Directory
        if args.recursive:
            pe_files = find_pe_files(args.path)
        else:
            pe_files = [f for f in os.listdir(args.path)
                        if is_supported_file(f)]
            pe_files = [os.path.join(args.path, f) for f in pe_files]

        print(f"Found {len(pe_files)} PE files to analyze")

        for pe_file in pe_files:
            all_orphaned.extend(analyze_dll_file(pe_file, args.debug))
    else:
        print(f"Path not found: {args.path}")
        return 1

    # Output results
    print(f"\n=== SUMMARY ===")
    print(f"Total orphaned icons found: {len(all_orphaned)}")

    if all_orphaned:
        print("\nOrphaned icons:")
        for icon in all_orphaned:
            print(f"  {icon['file']} - Icon ID: {icon['icon_id']}")

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write("Orphaned Icons Report\n")
            f.write("=" * 50 + "\n\n")
            for icon in all_orphaned:
                f.write(f"{icon['file']}\n")
                f.write(f"  Icon ID: {icon['icon_id']}\n\n")
        print(f"\nResults saved to: {args.output}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
