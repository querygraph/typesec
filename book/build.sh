#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p book/dist

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pandoc book/cover.md \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst

pandoc book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  --toc \
  --number-sections

pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" book/dist/typesec.pdf

pandoc book/cover.md book/typesec.md \
  -o book/dist/typesec.epub \
  --toc \
  --number-sections

/Applications/calibre.app/Contents/MacOS/ebook-convert \
  book/dist/typesec.epub \
  book/dist/typesec.mobi
