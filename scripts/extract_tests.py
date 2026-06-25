#!/usr/bin/env python3
"""Extract a trailing `#[cfg(test)] mod tests { .. }` from a Rust source file
into a sibling child-module file, replacing it with `#[cfg(test)] mod tests;`.

For `src/foo.rs` the tests land in `src/foo/tests.rs` (Rust 2018 child-module
lookup). Indentation is left as-is; run `cargo fmt` afterwards to normalise.

Usage: extract_tests.py <path/to/source.rs>
"""
import sys
import pathlib


def main(path_str: str) -> int:
    path = pathlib.Path(path_str)
    lines = path.read_text().splitlines()

    # Find the `mod tests {` line, then back up over its attributes.
    mod_idx = None
    for i, line in enumerate(lines):
        if line.strip() in ("mod tests {", "pub mod tests {"):
            mod_idx = i
            break
    if mod_idx is None:
        print(f"no `mod tests {{` in {path}", file=sys.stderr)
        return 1

    start = mod_idx
    while start > 0 and lines[start - 1].lstrip().startswith("#["):
        start -= 1
    # Drop a blank line and a decorative separator comment just above.
    while start > 0 and (
        lines[start - 1].strip() == ""
        or set(lines[start - 1].strip()) <= set("/─ ")
        and lines[start - 1].strip().startswith("//")
    ):
        start -= 1

    head = lines[:start]
    attrs = lines[start:mod_idx]  # e.g. #[cfg(test)]
    # Inner body is between `mod tests {` and the final closing `}`.
    if lines[-1].strip() != "}":
        print(f"{path}: test module is not at EOF (last line {lines[-1]!r})", file=sys.stderr)
        return 1
    inner = lines[mod_idx + 1:-1]

    # Rebuild source: head + attrs + `mod tests;`
    new_src = list(head)
    if new_src and new_src[-1].strip() != "":
        new_src.append("")
    new_src.extend(attrs)
    new_src.append("mod tests;")
    path.write_text("\n".join(new_src) + "\n")

    # Write child module file.
    tests_dir = path.with_suffix("")
    tests_dir.mkdir(exist_ok=True)
    tests_file = tests_dir / "tests.rs"
    tests_file.write_text("\n".join(inner).rstrip() + "\n")
    print(f"{path.name}: moved {len(inner)} test lines -> {tests_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
