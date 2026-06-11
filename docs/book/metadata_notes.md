# EPUB Metadata Notes

These notes come from debugging an EPUB that Amazon Send to Kindle rejected with
an internal error. The same checks should be useful for Grust and other book
projects that generate EPUBs with Pandoc or a similar pipeline.

## What Went Wrong

The generated EPUB was structurally readable, but the package metadata was too
thin. Its `EPUB/content.opf` had an identifier, date, and language, but it did
not have a real title or creator:

- no `dc:title`
- no `dc:creator`
- generated `UNTITLED` labels in the navigation files
- `Unknown` author in Calibre metadata output
- an empty generated `EPUB/text/title_page.xhtml` before the custom cover

Calibre could still inspect and convert the book, but it reported weak metadata
and threw an internal render error while probing generated frontmatter. Amazon's
error message was opaque, but the broken metadata profile was the clearest
portable failure mode.

After the metadata was fixed, Kindle accepted the EPUB but exposed a separate
layout problem: Pandoc had placed the navigation document first in the readable
spine, so the table of contents appeared before the cover. Pandoc also wrapped
the raw HTML cover in a generated top-level section with an ordinary
`<h1 class="unnumbered">Typesec</h1>`, which showed up as a title flushed at the
top of the page before the intended centered cover.

## Metadata Every EPUB Build Should Carry

Keep stable metadata in a checked-in metadata file, for example:

```yaml
---
title: Typesec
title_stem: typesec
subtitle: Type-Level Security for Agentic AI
author:
  - Alexy Khrabrov
lang: en-US
publisher: Chief Scientist
rights: Copyright Alexy Khrabrov
---
```

Then pass it to Pandoc:

```sh
pandoc cover.md manuscript.md \
  -o dist/book.epub \
  --toc \
  --number-sections \
  --metadata-file metadata.yaml \
  --metadata date="$(date -u +%F)" \
  --epub-title-page=false
```

The build date can stay dynamic, but title, subtitle, author, language,
publisher, and rights should live in source control. Keep `title_stem` there
too. It is the short distribution/catalog stem, not necessarily the visible
book title. Use it for Kindle metadata, versioned upload filenames, and
generated dist markers.

For books that are repeatedly sent to Kindle during development, the title
shown in the Kindle library should be generated from a short distribution title
and the current project version, for example `typesec (0.5.0)`. This short title
may be different from the full visible book title, especially for books with
long titles or titles containing colons. Keep the visible book title in the
checked-in metadata file, then post-process only the Kindle/catalog metadata in
`EPUB/content.opf` after Pandoc builds the EPUB:

```sh
version="0.5.0"
kindle_short_title="$(
  awk -F: '
    $1 ~ /^[[:space:]]*title_stem[[:space:]]*$/ {
      value = $2
      sub(/^[[:space:]]*/, "", value)
      sub(/[[:space:]]*$/, "", value)
      gsub(/^["'\'']|["'\'']$/, "", value)
      print value
      exit
    }
  ' metadata.yaml
)"
kindle_name="$kindle_short_title ($version)"

LIBRARY_TITLE="$kindle_name" perl -0pi -e '
  my $title = $ENV{LIBRARY_TITLE};
  s{<meta\s+refines="\#epub-title-1"\s+property="file-as">.*?</meta>\s*}{}s;
  s{<dc:title([^>]*)>.*?</dc:title>}{<dc:title$1>$title</dc:title>\n    <meta refines="#epub-title-1" property="file-as">$title</meta>}s;
' EPUB/content.opf
```

This lets the visible cover, table of contents, and navigation title remain a
clean book title while the Kindle library entry distinguishes uploaded editions.
After the post-processing step, `EPUB/content.opf` should contain:

```xml
<dc:title id="epub-title-1">typesec (0.5.0)</dc:title>
<meta refines="#epub-title-1" property="file-as">typesec (0.5.0)</meta>
```

while `EPUB/nav.xhtml`, `EPUB/toc.ncx`, and the cover XHTML should still display
the plain book title, for example `Typesec`.

If the cover needs to show which build it covers, do not hard-code the version
there either. Put a placeholder in the cover source:

```typst
#text(size: 12pt)[covers {{KINDLE_NAME}}]
```

and the matching EPUB cover HTML:

```html
<p style="font-size: 0.85em; margin: 0 0 1.1em;">covers {{KINDLE_NAME}}</p>
```

Then render a temporary cover during the build:

```sh
sed "s/{{KINDLE_NAME}}/$kindle_name/g" cover.md > "$tmpdir/cover.md"
```

The visible title remains `Typesec`; the small subtitle can say
`covers typesec (0.5.0)` because it is generated from the same catalog name as
the Kindle metadata.

## Kindle Library Title Rules

Treat the Kindle library card as a separate catalog surface from the book's
visible title page. The visible title, navigation, NCX, and table-of-contents
headings can and usually should remain stable, with the clean book title such
as `Typesec`. The generated catalog name, such as `typesec (0.5.0)`, belongs in
Kindle-facing metadata, upload filenames, `VERSION.md`, and any explicit small
build subtitle such as `covers typesec (0.5.0)`.

If a modern Kindle shows a bare lowercase title such as `typesec` even though
the intended catalog name is `typesec (0.5.0)`, look for catalog fallbacks rather
than changing the visible book. In the Typesec EPUB, the failure sources were:

- OPF package metadata that did not match the desired generated Kindle name
- a canonical upload filename, for example `typesec.epub`, which Kindle may use
  if it ignores, normalizes, or caches package metadata and strips the extension

Fix both surfaces from the same variable. Set the OPF title and title-sort
metadata to the intended library card string:

```xml
<dc:title id="epub-title-1">typesec (0.5.0)</dc:title>
<meta refines="#epub-title-1" property="file-as">typesec (0.5.0)</meta>
```

Then create a Send to Kindle upload copy with the same basename, and write a
small dist marker that records both the Kindle/catalog name and the date the
dist files were built:

```sh
cp dist/typesec.epub "dist/$kindle_name.epub"
{
  printf 'kindle_name: %s\n' "$kindle_name"
  printf 'built_at: %s\n' "$pubdate"
} > dist/VERSION.md
```

The upload copy can be byte-identical to the canonical EPUB. Its purpose is to
make a Kindle filename fallback match the intended metadata exactly.
`VERSION.md` gives downstream archive or delivery scripts a cheap way to see
which Kindle name and build date are inside the dist directory without opening
the EPUB.

## Why `--epub-title-page=false` Matters

When a project already provides a custom cover or title page, Pandoc can also
generate its own title page. In the failing EPUB, that produced an empty
`EPUB/text/title_page.xhtml` and pushed the real cover into a later chapter file.
Using `--epub-title-page=false` prevents that extra generated page and keeps the
custom cover as the first real content.

That option does not by itself guarantee the custom cover is first in the
readable spine. Check `EPUB/content.opf` after Pandoc writes the EPUB. For
Kindle-facing output, the first spine item should be the cover XHTML and the
navigation document should be non-linear:

```xml
<spine toc="ncx">
  <itemref idref="ch001_xhtml" />
  <itemref idref="nav" linear="no" />
  ...
</spine>
```

If Pandoc emits the nav item first, post-process the EPUB before MOBI/AZW3
conversion.

## Kindle-Friendly Cover HTML

Do not rely on modern web layout for the EPUB cover. Kindle renderers are more
predictable with simple centered text and margins than with flexbox or viewport
height tricks.

Prefer this style:

```html
<section epub:type="titlepage"
  style="text-align: center; page-break-after: always; padding-top: 8em;">
  <h1 style="font-size: 3.2em; margin: 0 0 0.05em;">Typesec</h1>
  ...
</section>
```

Avoid this style for Kindle-facing EPUBs:

```html
<section epub:type="titlepage"
  style="display: flex; flex-direction: column; justify-content: center;">
  ...
</section>
```

Also remove generated wrapper headings before the cover, such as:

```html
<h1 class="unnumbered">Typesec</h1>
```

The visible cover should contain only the intended custom title-page section.

## Build Invariants

After creating the EPUB, inspect the generated package rather than trusting the
source Markdown. A good metadata gate should fail the build if:

- `EPUB/content.opf` is missing `dc:title`
- `EPUB/content.opf` is missing `dc:creator`
- `EPUB/content.opf` is missing `dc:language`
- `EPUB/content.opf` is missing `dc:date`
- `EPUB/content.opf` is missing `dcterms:modified`
- the first readable spine item is not the cover XHTML
- the navigation document is not marked `linear="no"` after the cover
- the Kindle-facing OPF title does not match the generated short title and version
- the OPF title lacks a matching `file-as` refinement
- `dist/VERSION.md` does not include the generated Kindle name
- `dist/VERSION.md` does not include the dist build date
- `EPUB/toc.ncx` does not have the real book title
- `EPUB/nav.xhtml` does not have the real book title
- the Send to Kindle upload copy basename does not match the Kindle-facing OPF title
- any OPF, NCX, or nav file contains `UNTITLED` or `Unknown`
- `EPUB/text/title_page.xhtml` exists only as an empty generated title page
- the cover XHTML contains a generated wrapper heading before the custom cover
- the cover XHTML uses `display: flex`

Run this check before converting the EPUB to MOBI, AZW3, or any Kindle-facing
format. That way downstream artifacts cannot be generated from a broken EPUB.
If the generated Kindle name contains punctuation, such as parentheses in
`typesec (0.5.0)`, validators that use `grep -E` must escape the expected title
before interpolating it into a regex. Otherwise a correct OPF title can fail the
check because the punctuation is interpreted as regex syntax.

## Practical Verification Commands

Inspect the package metadata:

```sh
unzip -p dist/book.epub EPUB/content.opf
```

Check the catalog title exactly:

```sh
unzip -p dist/book.epub EPUB/content.opf |
  rg 'dc:title|property="file-as"'
ebook-meta dist/book.epub
```

Inspect navigation titles:

```sh
unzip -p dist/book.epub EPUB/toc.ncx
unzip -p dist/book.epub EPUB/nav.xhtml
```

Check that the Kindle upload filename cannot fall back to a lowercase title:

```sh
ls -lh "dist/typesec (0.5.0).epub"
cmp -s dist/book.epub "dist/typesec (0.5.0).epub"
cat dist/VERSION.md
```

For example, `dist/VERSION.md` should look like:

```text
kindle_name: typesec (0.5.0)
built_at: 2026-06-10
```

List generated files and look for unwanted title pages:

```sh
unzip -l dist/book.epub
```

Ask Calibre how it sees the book:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-meta dist/book.epub
```

Smoke-test Kindle-style conversion:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-convert dist/book.epub /tmp/book.azw3
```

Calibre accepting the EPUB does not prove Amazon will accept it, but it is a
useful local check. The stronger protection is a build-time metadata validator
that rejects weak or generated fallback metadata before any ebook conversion
happens.
