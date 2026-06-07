# Book Build Notes

## Separate Cover Page

Use `book/cover.md` as a standalone cover source and keep it separate from the
main manuscript. The file contains two raw blocks:

- A Typst block for the PDF cover.
- An HTML block for the EPUB and MOBI cover.

Keep the visible text synchronized between both blocks.

## PDF Build

Render the cover by itself:

```sh
pandoc book/cover.md \
  -o "$tmpdir/cover.pdf" \
  --pdf-engine=typst
```

Render the book body separately, with the table of contents:

```sh
pandoc book/typesec.md \
  -o "$tmpdir/body.pdf" \
  --pdf-engine=typst \
  --toc \
  --number-sections
```

Merge the cover before the body:

```sh
pdfunite "$tmpdir/cover.pdf" "$tmpdir/body.pdf" book/dist/typesec.pdf
```

This ensures the PDF starts with a full cover page, followed by the table of
contents and the numbered body.

## EPUB and MOBI Build

Pass the cover file before the manuscript:

```sh
pandoc book/cover.md book/typesec.md \
  -o book/dist/typesec.epub \
  --toc \
  --number-sections
```

Convert the EPUB to MOBI:

```sh
ebook-convert book/dist/typesec.epub book/dist/typesec.mobi
```

On this machine, Calibre's converter is available at:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-convert
```
