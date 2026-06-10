#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p docs/book/dist

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pandoc docs/book/cover.md \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst

pandoc docs/book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  --toc \
  --number-sections

pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" docs/book/dist/typesec.pdf

pandoc docs/book/cover.md docs/book/typesec.md \
  -o docs/book/dist/typesec.epub \
  --toc \
  --number-sections

/Applications/calibre.app/Contents/MacOS/ebook-convert \
  docs/book/dist/typesec.epub \
  docs/book/dist/typesec.mobi
