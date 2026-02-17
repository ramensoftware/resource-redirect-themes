import argparse
import os
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

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
