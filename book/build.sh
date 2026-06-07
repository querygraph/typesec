#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p book/dist

pandoc book/typesec.md \
  -o book/dist/typesec.pdf \
  --pdf-engine=typst \
  --toc \
  --number-sections

pandoc book/typesec.md \
  -o book/dist/typesec.epub \
  --toc \
  --number-sections

/Applications/calibre.app/Contents/MacOS/ebook-convert \
  book/dist/typesec.epub \
  book/dist/typesec.mobi
