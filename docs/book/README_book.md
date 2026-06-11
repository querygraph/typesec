# Book Build Notes

## Separate Cover Page

Use `docs/book/cover.md` as a standalone cover source and keep it separate from the
main manuscript. The file contains two raw blocks:

- A Typst block for the PDF cover.
- An HTML block for the EPUB and MOBI cover.

Keep the visible text synchronized between both blocks. The visible cover stays
stable and does not include the package version; versioning is reserved for
Kindle-facing EPUB metadata. The Typst cover block disables page numbering so
the standalone cover page has no printed page number.

## Metadata

Keep stable EPUB metadata in `docs/book/metadata.yaml`. The build script passes
that file to Pandoc and overrides the publication date with the current UTC
date. After Pandoc writes the EPUB, the layout fixer updates only the OPF
package title used by Kindle libraries to the generated `kindle_name`, for
example `typesec (0.4.0)`. The name comes from `title_stem` in
`docs/book/metadata.yaml` plus `[workspace.package].version` in the root
`Cargo.toml`.

After building the EPUB, `docs/book/check_epub_metadata.sh` verifies the package
metadata, NCX title, nav title, cover-first spine order, and the absence of
Pandoc's generated empty title page. The build stops before MOBI conversion if
the EPUB falls back to `UNTITLED`, `Unknown`, missing title, author, language,
or date fields, or if the readable spine starts with the navigation document
instead of the cover.

## PDF Build

Render the cover by itself:

```sh
pandoc "$tmpdir/cover.md" \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst
```

Render the book body separately, with the table of contents:

```sh
pandoc docs/book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  --toc \
  --number-sections
```

Merge the cover before the body:

```sh
pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" docs/book/dist/typesec.pdf
```

This ensures the PDF starts with a full unnumbered cover page, followed by the
table of contents and the numbered body. Printed page numbers start after the
cover.

## EPUB and MOBI Build

Pass the cover file before the manuscript:

```sh
pandoc "$tmpdir/cover.md" docs/book/typesec.md \
  -o docs/book/dist/typesec.epub \
  --toc \
  --number-sections \
  --metadata-file docs/book/metadata.yaml \
  --metadata date="$pubdate" \
  --epub-title-page=false
```

The metadata file keeps the EPUB package from falling back to `UNTITLED` and
`Unknown` author, and `--epub-title-page=false` prevents Pandoc from emitting an
empty generated title page before the custom cover.

The visible cover, NCX title, and navigation title still say `Typesec`, while
the OPF metadata title used by Kindle libraries comes from a short distribution
title plus the workspace version, for example `typesec (0.4.0)`. The build keeps
the stable title-stem EPUB at `docs/book/dist/typesec.epub` and creates a
versioned Send to Kindle symlink, `docs/book/dist/typesec (0.4.0).epub`, that
points back to it. `docs/book/dist/VERSION.md` records the Kindle name, build
date, stable EPUB filename, and symlink filename.

`docs/book/fix_epub_layout.sh` then repairs Kindle-facing reading order by
placing the custom cover first in the EPUB spine, marking the navigation
document as `linear="no"`, and removing Pandoc's generated top-level cover
heading. The HTML cover uses simple centered text and margins rather than
flexbox so Kindle renderers do not place the title incorrectly.

Convert the EPUB to MOBI:

```sh
ebook-convert docs/book/dist/typesec.epub docs/book/dist/typesec.mobi
```

On this machine, Calibre's converter is available at:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-convert
```
