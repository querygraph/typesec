#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p docs/book/dist

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

version="$(
  awk '
    /^\[workspace\.package\]/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version[[:space:]]*=/ {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.toml
)"

if [[ -z "$version" ]]; then
  echo "could not read workspace package version from Cargo.toml" >&2
  exit 1
fi

pubdate="$(date -u +%F)"
kindle_short_title="$(
  if [[ -f docs/book/metadata.yaml ]]; then
    awk -F: '
      $1 ~ /^[[:space:]]*title_stem[[:space:]]*$/ {
        value = $2
        sub(/^[[:space:]]*/, "", value)
        sub(/[[:space:]]*$/, "", value)
        gsub(/^["'\'']|["'\'']$/, "", value)
        print value
        exit
      }
    ' docs/book/metadata.yaml
  fi
)"

if [[ -z "$kindle_short_title" ]]; then
  kindle_short_title="typesec"
fi

kindle_name="$kindle_short_title ($version)"
kindle_epub="docs/book/dist/$kindle_name.epub"

{
  printf 'kindle_name: %s\n' "$kindle_name"
  printf 'built_at: %s\n' "$pubdate"
} > docs/book/dist/VERSION.md

sed "s/{{KINDLE_NAME}}/$kindle_name/g" docs/book/cover.md > "$tmpdir/cover.md"

pandoc "$tmpdir/cover.md" \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst

pandoc docs/book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  --toc \
  --number-sections

pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" docs/book/dist/typesec.pdf

pandoc "$tmpdir/cover.md" docs/book/typesec.md \
  -o docs/book/dist/typesec.epub \
  --toc \
  --number-sections \
  --metadata-file docs/book/metadata.yaml \
  --metadata date="$pubdate" \
  --epub-title-page=false

docs/book/fix_epub_layout.sh docs/book/dist/typesec.epub "$kindle_name"
docs/book/check_epub_metadata.sh docs/book/dist/typesec.epub "$kindle_name"
cp docs/book/dist/typesec.epub "$kindle_epub"

/Applications/calibre.app/Contents/MacOS/ebook-convert \
  docs/book/dist/typesec.epub \
  docs/book/dist/typesec.mobi
