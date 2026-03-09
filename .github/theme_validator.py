import argparse
import os
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

from pe_tools import parse_pe

from list_resources import get_resource_types
from find_orphaned_icons import analyze_icon_resources as find_orphaned_icons_analyze


def get_pe_section_names(file_path: Path) -> list[str]:
    """
    Parse PE file and return list of section names.
    Returns empty list if not a valid PE file.
    """
    try:
        with open(file_path, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                return []

            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]

            # Seek to PE header
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                return []

            # Read COFF header
            coff_header = f.read(20)
            if len(coff_header) < 20:
                return []

            # Extract number of sections and size of optional header
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            optional_header_size = struct.unpack('<H', coff_header[16:18])[0]

            # Skip optional header
            f.seek(f.tell() + optional_header_size)

            # Read section headers
            section_names = []
            for _ in range(num_sections):
                section_header = f.read(40)
                if len(section_header) < 40:
                    break

                # Section name is first 8 bytes, null-terminated
                name_bytes = section_header[:8]
                name = name_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
                section_names.append(name)

            return section_names

    except (IOError, struct.error, UnicodeDecodeError):
        return []


def find_file_case_insensitive(target_path: Path) -> Path | None:
    """
    Find a file in a case-insensitive manner on case-sensitive file systems.
    Returns the actual path if found, None otherwise.
    """
    if target_path.exists():
        return target_path

    # On case-insensitive file systems (like Windows), just return None if not found
    if os.name == 'nt':
        return None

    # On case-sensitive file systems (like Linux), search case-insensitively
    parent = target_path.parent
    target_name = target_path.name.lower()

    if not parent.exists():
        # Try to find parent directory case-insensitively
        parent_found = find_file_case_insensitive(parent)
        if not parent_found:
            return None
        parent = parent_found

    try:
        for item in parent.iterdir():
            if item.name.lower() == target_name:
                return item
    except (OSError, PermissionError):
        pass

    return None


def check_path(path: Path):
    theme_file = path / "theme.ini"

    R"""
    Example theme.ini content:

    ```
    [redirections]
    %SystemRoot%\System32\imageres.dll=.\Windhawk Resources\imageres.dll
    %SystemRoot%\System32\imagesp1.dll=.\Windhawk Resources\imageresp1.dll
    %SystemRoot%\System32\shell32.dll=.\Windhawk Resources\shell32.dll
    %SystemRoot%\System32\zipfldr.dll=.\Windhawk Resources\zipfldr.dll
    ```

    This function verifies that each redirection in the theme.ini file
    points to a valid file within the theme directory.
    """

    errors = []

    if not theme_file.exists():
        errors.append(f"theme.ini not found in {path}")
        # Print all errors and raise
        for error in errors:
            print(f"  ERROR: {error}")
        if errors:
            raise ValueError(f"Theme validation failed for {path.name}")
        return

    import configparser

    config = configparser.ConfigParser()
    config.read(theme_file)

    if 'redirections' not in config:
        errors.append("No [redirections] section found in theme.ini")
    else:
        redirections = config['redirections']
        referenced_files = set()

        for source, target in redirections.items():
            # Convert relative path to absolute path within the theme directory
            target_path = path / target.replace('\\', '/')
            referenced_files.add(target_path)

            if not target_path.exists():
                # On Linux, check if the target exists in a case-insensitive manner
                actual_path = find_file_case_insensitive(target_path)
                if actual_path:
                    target_path = actual_path
                    referenced_files.add(target_path)
                else:
                    errors.append(
                        f"Redirection target not found: {target} -> {target_path}"
                    )
                    continue
            elif not target_path.is_file():
                errors.append(f"Redirection target is not a file: {target_path}")
                continue

            # Validate PE file structure
            pe_errors = validate_pe_file(target_path)
            errors.extend(pe_errors)

        # Check for unreferenced files in the theme directory
        all_files = set()
        for item in path.rglob('*'):
            if item.is_file() and item.name != 'theme.ini':
                all_files.add(item)

        unreferenced_files = all_files - referenced_files
        for unreferenced_file in unreferenced_files:
            if unreferenced_file.name.lower() in ["preview.png", "preview.bmp"]:
                continue
            rel_path = unreferenced_file.relative_to(path)
            errors.append(f"Unreferenced file found: {rel_path}")

    # Print all errors and raise if any were found
    for error in errors:
        print(f"  ERROR: {error}")

    if errors:
        raise ValueError(f"Theme validation failed for {path.name}")


def validate_pe_file(file_path: Path) -> list[str]:
    """
    Validate that the file is a PE file with a single .rsrc section.
    Returns a list of error messages, empty if valid.
    """
    errors = []

    file_size = file_path.stat().st_size
    if file_size == 0:
        errors.append(f"Empty file (0 bytes): {file_path.name}")
        return errors

    # Get section names using our custom parser
    section_names = get_pe_section_names(file_path)

    if not section_names:
        errors.append(f"Not a valid PE file ({file_size} bytes): {file_path.name}")
        return errors

    if section_names != ['.rsrc']:
        errors.append(
            f"PE file should have only .rsrc section, found: {section_names}: "
            f"{file_path.name}"
        )

    # Validate resource content - check that all resources are icons
    resource_errors = validate_resource_types(file_path)
    errors.extend(resource_errors)

    # Validate actual image data integrity
    image_errors = validate_resource_images(file_path)
    errors.extend(image_errors)

    # Check for orphaned icons
    try:
        orphaned_icons, _ = find_orphaned_icons_analyze(file_path)
    except Exception as e:
        errors.append(f"Failed to analyze icons in {file_path.name}: {e}")
        return errors

    if orphaned_icons:
        error_msg = f"Found {len(orphaned_icons)} orphaned icons in {file_path.name}: "
        error_msg += ', '.join(str(orphan) for orphan in orphaned_icons)
        errors.append(error_msg)

    return errors


def validate_png_data(data: bytes) -> str | None:
    """
    Validate PNG data by walking chunks to verify IEND is reached.
    Returns an error string if invalid, None if valid.
    """
    signature = b'\x89PNG\r\n\x1a\n'
    if len(data) < 8 or data[:8] != signature:
        return "missing PNG signature"

    offset = 8
    while offset + 8 <= len(data):
        chunk_length = struct.unpack('>I', data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_end = offset + 12 + chunk_length  # 4 length + 4 type + data + 4 CRC
        if chunk_type == b'IEND':
            trailing = len(data) - chunk_end
            if trailing > 0:
                return f"trailing data after IEND ({trailing} extra bytes)"
            return None  # Valid
        offset = chunk_end

    return f"truncated (no IEND chunk, {len(data)} bytes)"


def validate_dib_data(data: bytes, is_icon: bool = True) -> str | None:
    """
    Validate DIB (device-independent bitmap) data.
    For icons (is_icon=True): height is doubled (includes AND mask).
    For bitmaps (is_icon=False): height is as-is, no AND mask.
    Returns an error string if invalid, None if valid.
    """
    if len(data) < 40:
        return f"too short for DIB header ({len(data)} bytes)"

    header_size = struct.unpack('<I', data[:4])[0]
    if header_size not in (40, 108, 124):
        return f"invalid DIB header size {header_size}"

    width, height = struct.unpack('<ii', data[4:12])
    _planes, bit_count = struct.unpack('<HH', data[12:16])
    compression = struct.unpack('<I', data[16:20])[0]

    if is_icon:
        actual_height = abs(height) // 2  # Icons store double height for AND mask
    else:
        actual_height = abs(height)
    actual_width = abs(width)

    if actual_width == 0 or actual_height == 0:
        return f"zero dimensions ({actual_width}x{actual_height})"

    if is_icon and (actual_width > 1024 or actual_height > 1024):
        return f"unreasonable dimensions ({actual_width}x{actual_height})"

    # Skip size check for compressed bitmaps (RLE8=1, RLE4=2)
    if compression != 0:
        return None

    # Calculate row bytes: ((width * bit_count + 31) / 32) * 4
    row_bytes = ((actual_width * bit_count + 31) // 32) * 4

    # Color table size for indexed formats
    if bit_count <= 8:
        clr_used = struct.unpack('<I', data[32:36])[0]
        if clr_used > 0:
            color_table_size = clr_used * 4
        else:
            color_table_size = (1 << bit_count) * 4
    else:
        color_table_size = 0

    expected_size = header_size + color_table_size + row_bytes * actual_height
    if is_icon:
        and_mask_row = ((actual_width + 31) // 32) * 4
        expected_size += and_mask_row * actual_height

    if len(data) < expected_size:
        return (
            f"data too short for {actual_width}x{actual_height} {bit_count}bit "
            f"(expected {expected_size}, got {len(data)} bytes)"
        )

    trailing = len(data) - expected_size
    if trailing > 0:
        return (
            f"trailing data after {actual_width}x{actual_height} {bit_count}bit "
            f"(expected {expected_size}, got {len(data)}, {trailing} extra bytes)"
        )

    return None


def validate_resource_images(file_path: Path) -> list[str]:
    """
    Validate the actual image data of icon and bitmap resources in a PE file.
    Detects truncated PNGs, corrupt DIBs, etc.
    Returns a list of error messages.
    """
    errors = []

    try:
        with open(file_path, 'rb') as f:
            pe = parse_pe(f.read())
        resources = pe.parse_resources()
    except Exception as e:
        errors.append(f"Failed to parse resources in {file_path.name}: {e}")
        return errors

    if not resources:
        return errors

    # Validate RT_ICON (type 3) resources
    if 3 in resources:
        for icon_id, languages in resources[3].items():
            for _lang_id, icon_data in languages.items():
                data = bytes(icon_data)
                if len(data) == 0:
                    errors.append(
                        f"Empty RT_ICON {icon_id} in {file_path.name}"
                    )
                    continue

                is_png = data[:8] == b'\x89PNG\r\n\x1a\n'
                if is_png:
                    error = validate_png_data(data)
                else:
                    error = validate_dib_data(data)

                if error:
                    fmt = "PNG" if is_png else "DIB"
                    errors.append(
                        f"Invalid {fmt} in RT_ICON {icon_id} of "
                        f"{file_path.name}: {error}"
                    )

    # Validate RT_BITMAP (type 2) resources
    if 2 in resources:
        for bmp_id, languages in resources[2].items():
            for _lang_id, bmp_data in languages.items():
                data = bytes(bmp_data)
                if len(data) == 0:
                    errors.append(
                        f"Empty RT_BITMAP {bmp_id} in {file_path.name}"
                    )
                    continue

                error = validate_dib_data(data, is_icon=False)
                if error:
                    errors.append(
                        f"Invalid DIB in RT_BITMAP {bmp_id} of "
                        f"{file_path.name}: {error}"
                    )

    return errors


def validate_resource_types(file_path: Path) -> list[str]:
    """
    Validate that all resources in the PE file are icons using Resource Hacker.
    Returns a list of error messages for non-icon resources.
    """
    errors = []

    types = get_resource_types(str(file_path))
    if len(types) == 0:
        errors.append(f"No resources found in {file_path.name}")
        return errors

    for type in types:
        if type not in [
            1,  # RT_CURSOR
            2,  # RT_BITMAP
            3,  # RT_ICON
            12,  # RT_GROUP_CURSOR
            14,  # RT_GROUP_ICON
            'PNG',
            'IMAGE',
        ]:
            errors.append(f"Non-icon resource type found in {file_path.name}: {type}")

    return errors


def validate_packed_themes(zip_files):
    """Validate packed theme .zip files."""
    has_errors = False

    for zip_file in zip_files:
        zip_path = Path(zip_file)
        if not zip_path.exists():
            print(f"ERROR: Packed theme file not found: {zip_path}")
            has_errors = True
            continue

        print(f"Checking packed theme: {zip_path.name}")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Extract the zip file
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_path)

                # Find the theme directory (should be a single directory in the zip)
                theme_dirs = [d for d in temp_path.iterdir() if d.is_dir()]
                if len(theme_dirs) != 1:
                    print(
                        "ERROR: Expected exactly one theme directory in"
                        f" {zip_path.name}, found {len(theme_dirs)}"
                    )
                    has_errors = True
                    continue

                theme_dir = theme_dirs[0]
                check_path(theme_dir)
                print(f"[+] Packed theme validated: {zip_path.name}")
        except Exception as e:
            print(f"Invalid packed theme: {zip_path.name} ({e})")
            has_errors = True

    if has_errors:
        sys.exit(1)


def validate_single_theme(theme_name):
    """Validate a single unpacked theme by name."""
    themes_path = Path("unpacked")

    if not themes_path.exists():
        print(f"ERROR: Themes directory not found: {themes_path}")
        sys.exit(1)

    theme_path = themes_path / theme_name
    if not theme_path.exists():
        print(f"ERROR: Theme folder not found: {theme_path}")
        sys.exit(1)
    if not theme_path.is_dir():
        print(f"ERROR: {theme_path} is not a directory")
        sys.exit(1)

    print(f"Checking theme: {theme_name}")
    try:
        check_path(theme_path)
        print(f"[+] Theme validated: {theme_name}")
    except Exception as e:
        print(f"Invalid theme: {theme_name} ({e})")
        sys.exit(1)


def validate_all_themes():
    """Validate all unpacked themes in the themes directory."""
    themes_path = Path("unpacked")

    if not themes_path.exists():
        print(f"ERROR: Themes directory not found: {themes_path}")
        sys.exit(1)

    for subpath in themes_path.iterdir():
        if subpath.is_dir():
            print(f"Checking theme: {subpath.name}")
            try:
                check_path(subpath)
                print(f"[+] Theme validated: {subpath.name}")
            except Exception as e:
                print(f"Invalid theme: {subpath.name} ({e})")


def main():
    parser = argparse.ArgumentParser(description="Validate icon theme folders")
    parser.add_argument(
        "--theme", "-t", type=str, help="Check only a specific theme folder by name"
    )
    parser.add_argument(
        "--packed_themes", nargs='+', help="Validate packed theme .zip files"
    )
    args = parser.parse_args()

    if args.packed_themes:
        validate_packed_themes(args.packed_themes)
    elif args.theme:
        validate_single_theme(args.theme)
    else:
        validate_all_themes()


if __name__ == "__main__":
    main()
