#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p docs/book/dist

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Render inline ```mermaid blocks to PNG at build time (see docs/book/mermaid.lua).
# The filter writes images into $MERMAID_OUT (absolute, so EPUB/PDF resolve them).
mermaid_out="$tmpdir/diagrams"
mkdir -p "$mermaid_out"
export MERMAID_OUT="$mermaid_out"
export MERMAID_PUPPETEER="$PWD/docs/book/puppeteer-config.json"
mermaid_filter=(--lua-filter docs/book/mermaid.lua)

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

# The visible title/cover stays clean (no commit hash). The delivery links carry
# a `<version>-<short-hash>` stamp so each built EPUB/PDF is traceable to a commit.
kindle_name="$kindle_short_title ($version)"
githash="$(git rev-parse --short=6 HEAD 2>/dev/null || echo nogit)"
version_stamp="$version-$githash"
link_stem="$kindle_short_title ($version_stamp)"
stable_epub="docs/book/dist/$kindle_short_title.epub"
stable_pdf="docs/book/dist/$kindle_short_title.pdf"
versioned_epub="docs/book/dist/$link_stem.epub"
versioned_pdf="docs/book/dist/$link_stem.pdf"

{
  printf 'kindle_name: %s\n' "$kindle_name"
  printf 'version_stamp: %s\n' "$version_stamp"
  printf 'built_at: %s\n' "$pubdate"
  printf 'epub_file: %s.epub\n' "$kindle_short_title"
  printf 'pdf_file: %s.pdf\n' "$kindle_short_title"
  printf 'epub_link: %s.epub\n' "$link_stem"
  printf 'pdf_link: %s.pdf\n' "$link_stem"
} > docs/book/dist/VERSION.md

sed "s/{{KINDLE_NAME}}/$kindle_name/g" docs/book/cover.md > "$tmpdir/cover.md"

pandoc "$tmpdir/cover.md" \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst

pandoc docs/book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  "${mermaid_filter[@]}" \
  --toc \
  --number-sections

pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" docs/book/dist/typesec.pdf

pandoc "$tmpdir/cover.md" docs/book/typesec.md \
  -o docs/book/dist/typesec.epub \
  "${mermaid_filter[@]}" \
  --toc \
  --number-sections \
  --metadata-file docs/book/metadata.yaml \
  --metadata date="$pubdate" \
  --css docs/book/epub.css \
  --epub-title-page=false

docs/book/fix_epub_layout.sh docs/book/dist/typesec.epub "$kindle_name"
# Refresh the versioned delivery links (EPUB + PDF) for this build's stamp.
find docs/book/dist -maxdepth 1 \
  \( -name "$kindle_short_title (*).epub" -o -name "$kindle_short_title (*).pdf" \) -delete
ln -s "$(basename "$stable_epub")" "$versioned_epub"
ln -s "$(basename "$stable_pdf")" "$versioned_pdf"
docs/book/check_epub_metadata.sh docs/book/dist/typesec.epub "$kindle_name"

/Applications/calibre.app/Contents/MacOS/ebook-convert \
  docs/book/dist/typesec.epub \
  docs/book/dist/typesec.mobi
