import argparse
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

# Theme paths must look like: themes/icons/<folder>/<file>.zip
# This single pattern enforces both the .zip extension and that the theme
# lives under the author's folder inside themes/icons/.
PATH_PATTERN = re.compile(r'^themes/icons/([^/]+)/[^/]+\.zip$')


def load_known_files(known_files_path: str) -> set[str]:
    """
    Load the set of repo-relative paths that are known to exist.

    The file may be newline-delimited or NUL-delimited (e.g. produced by
    `git ls-tree -z`), so existence can be checked in CI without fetching
    every theme blob.
    """
    with open(known_files_path, encoding='utf-8') as f:
        content = f.read()

    separator = '\0' if '\0' in content else '\n'
    known = set()
    for entry in content.split(separator):
        entry = entry.strip()
        if entry:
            known.add(entry.replace('\\', '/'))
    return known


def path_exists(path: str, known_files: set[str] | None) -> bool:
    if known_files is not None:
        return path in known_files
    return Path(path).is_file()


def validate_themes_yaml(
    themes_yaml_path: str, known_files: set[str] | None = None
) -> list[str]:
    """
    Validate the structure and consistency of themes.yaml.

    Returns a list of error strings (empty if valid).

    known_files: optional set of repo-relative file paths known to exist. When
    None, existence is checked against the local filesystem.
    """
    try:
        with open(themes_yaml_path, encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        return [f"Failed to read {themes_yaml_path}: {e}"]

    if not isinstance(data, list) or not data:
        return [f"{themes_yaml_path} must be a non-empty list of author entries"]

    errors: list[str] = []
    all_paths: list[str] = []       # for duplicate detection across the file
    folder_owner: dict[str, int] = {}  # folder -> index of the entry that owns it

    for i, entry in enumerate(data):
        where = f"entry #{i + 1}"
        if not isinstance(entry, dict):
            errors.append(f"{where}: expected a mapping, got {type(entry).__name__}")
            continue

        author = entry.get('author')
        if isinstance(author, str) and author.strip():
            where = f"author {author!r}"
        else:
            errors.append(f"{where}: missing or empty 'author'")

        link = entry.get('link')
        if not isinstance(link, str) or not link.strip():
            errors.append(f"{where}: missing or empty 'link'")

        themes = entry.get('themes')
        if not isinstance(themes, list) or not themes:
            errors.append(f"{where}: 'themes' must be a non-empty list")
            continue

        entry_folders: set[str] = set()
        for j, theme in enumerate(themes):
            tloc = f"{where}, theme #{j + 1}"
            if not isinstance(theme, dict):
                errors.append(
                    f"{tloc}: expected a mapping, got {type(theme).__name__}"
                )
                continue

            name = theme.get('name')
            if isinstance(name, str) and name.strip():
                tloc = f"{where}, theme {name!r}"
            else:
                errors.append(f"{tloc}: missing or empty 'name'")

            original_author = theme.get('originalAuthor')
            if original_author is not None and (
                not isinstance(original_author, str) or not original_author.strip()
            ):
                errors.append(
                    f"{tloc}: 'originalAuthor' must be a non-empty string when present"
                )

            path = theme.get('path')
            if not isinstance(path, str) or not path.strip():
                errors.append(f"{tloc}: missing or empty 'path'")
                continue

            all_paths.append(path)

            match = PATH_PATTERN.match(path)
            if not match:
                errors.append(
                    f"{tloc}: path {path!r} must match "
                    f"'themes/icons/<folder>/<file>.zip'"
                )
                continue

            entry_folders.add(match.group(1))

            if not path_exists(path, known_files):
                errors.append(f"{tloc}: referenced file does not exist: {path}")

        # All of an author's themes must live under a single themes/icons/<folder>/.
        if len(entry_folders) > 1:
            errors.append(
                f"{where}: themes span multiple folders {sorted(entry_folders)}; "
                f"all of an author's themes must live under one themes/icons/<folder>/"
            )

        # Each folder must belong to exactly one author entry.
        for folder in entry_folders:
            owner = folder_owner.setdefault(folder, i)
            if owner != i:
                errors.append(
                    f"{where}: folder 'themes/icons/{folder}/' is already used by "
                    f"a different author entry"
                )

    # No duplicate paths across the whole file.
    for path, count in Counter(all_paths).items():
        if count > 1:
            errors.append(f"duplicate path used {count} times: {path}")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate themes.yaml structure and consistency"
    )
    parser.add_argument(
        '--themes-yaml', default='themes.yaml', help='Path to themes.yaml'
    )
    parser.add_argument(
        '--known-files',
        help='Optional file listing repo-relative paths known to exist '
        '(newline- or NUL-delimited). When omitted, existence is checked '
        'against the local filesystem.',
    )
    args = parser.parse_args()

    known_files = None
    if args.known_files:
        known_files = load_known_files(args.known_files)

    errors = validate_themes_yaml(args.themes_yaml, known_files)

    if errors:
        print(f"themes.yaml validation FAILED with {len(errors)} error(s):")
        for error in errors:
            print(f"  ERROR: {error}")
        sys.exit(1)

    print("themes.yaml validation passed.")


if __name__ == "__main__":
    main()
