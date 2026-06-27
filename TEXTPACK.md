# Preparing a Ulysses TextPack from a Typesec blog post

How to turn a Markdown blog post that uses diagrams (e.g.
`docs/blog/<name>/post.md`) into a self-contained **`.textpack`** that imports
cleanly into Ulysses — including on iOS, where external image paths and
`mermaid` code blocks do not render.

A `.textpack` is the right deliverable because it bundles the Markdown text *and*
the image assets into one importable package. Pasting raw Markdown into Ulysses
(or Ghost) instead tends to produce two problems this guide also fixes:

- **Ragged lines with big vertical gaps** — caused by hard-wrapped prose; the
  editor treats every newline as a line break. Fix: reflow to one line per
  paragraph.
- **Missing diagrams** — Ulysses/Ghost do not render `mermaid`. Fix: pre-render
  diagrams to PNG and reference the images.

## Format

A TextBundle is a folder; a TextPack is that folder zipped:

```
<name>.textbundle/
  text.markdown          # the post (Markdown / Markdown XL)
  info.json              # {"version":2,"type":"net.daringfireball.markdown","transient":false}
  assets/<diagram>.png   # bundled images, referenced as assets/<diagram>.png
```

Zip the `.textbundle` directory (with the directory as the top-level entry) to
`<name>.textpack`. Ulysses imports the `.textpack` via the share sheet or
**＋ → Import**.

## Prerequisites

- `mmdc` — the Mermaid CLI (`@mermaid-js/mermaid-cli`). Renders fenced mermaid to
  PNG. No puppeteer config is normally needed; if Chrome sandbox errors appear,
  pass `--puppeteerConfigFile docs/book/puppeteer-config.json` (it sets
  `--no-sandbox`).
- `python3` — for the reflow and bundling steps below (no third-party packages).

## Steps

### 1. Reflow prose to one line per paragraph

Hard wrapping is what makes the text render ragged with paragraph gaps. Collapse
each prose paragraph to a single soft-wrapping line; leave code fences, headings,
blockquotes, tables, and image lines untouched, and collapse each list item to a
single line (so multi-line items don't fragment).

```python
import re
src = "docs/blog/announcing-typesec/post.md"
lines = open(src).read().split("\n")
out, buf, in_code = [], [], False
list_re   = re.compile(r"^\s*([-*+]|\d+\.)\s+")
struct_re = re.compile(r"^(#|>|\||!\[|(---|\*\*\*|___)\s*$)")
def flush():
    if buf: out.append(" ".join(buf)); buf.clear()
for ln in lines:
    s = ln.strip()
    if s.startswith("```"):
        flush(); out.append(ln); in_code = not in_code; continue
    if in_code: out.append(ln); continue            # code verbatim
    if s == "": flush(); out.append(""); continue   # blank = paragraph break
    if struct_re.match(s): flush(); out.append(ln); continue  # structural line
    if list_re.match(s): flush(); buf.append(s); continue     # new list item
    buf.append(s)                                   # prose / item continuation
flush()
open(src, "w").write("\n".join(out).rstrip("\n") + "\n")
```

Sanity checks: the fence count (`grep -c '```'`) must be unchanged, and code
blocks must remain multi-line.

### 2. Render the diagrams to PNG

Keep `mermaid` sources in a `diagrams/` directory next to the post (one `.mmd`
per diagram). Render each at 2× on a **white** background (safe for both light
and dark editors):

```sh
cd docs/blog/announcing-typesec
for n in diagrams/*.mmd; do
  mmdc -i "$n" -o "${n%.mmd}.png" -b white -s 2
done
```

If you edit a diagram's content, edit the `.mmd` source and re-render.

### 3. Point the post at the images

In the canonical post, each diagram is an image reference
(`![caption](diagrams/<name>.png)`). For the TextPack the bundler rewrites
`diagrams/...` to `assets/...` (next step), so the repo post keeps the
`diagrams/` path and the bundle is self-contained.

### 4. Build the `.textpack`

```python
import re, os, json, zipfile, shutil
base = "docs/blog/announcing-typesec"
post = open(f"{base}/post.md").read()
ddir = f"{base}/diagrams"
out  = f"{base}/dist"                          # committed, next to the post
os.makedirs(out, exist_ok=True)
tb   = f"{out}/announcing-typesec.textbundle"
shutil.rmtree(tb, ignore_errors=True); os.makedirs(f"{tb}/assets", exist_ok=True)
imgs = set(re.findall(r"!\[[^\]]*\]\(diagrams/([a-z0-9-]+\.png)\)", post))
text = re.sub(r"\(diagrams/([a-z0-9-]+\.png)\)", r"(assets/\1)", post)  # diagrams/ -> assets/
open(f"{tb}/text.markdown", "w").write(text)
json.dump({"version": 2, "type": "net.daringfireball.markdown", "transient": False},
          open(f"{tb}/info.json", "w"))
for n in imgs: shutil.copy(f"{ddir}/{n}", f"{tb}/assets/{n}")
pack = f"{out}/announcing-typesec.textpack"
if os.path.exists(pack): os.remove(pack)
with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(tb):
        for fn in files:
            p = os.path.join(root, fn); z.write(p, os.path.relpath(p, out))
shutil.rmtree(tb)   # keep only the .textpack in dist/, not the unzipped bundle
```

The zip's top entry must be `<name>.textbundle/` (verify with
`zipfile.ZipFile(pack).namelist()`).

## Fallback: a single self-contained Markdown file

If a `.textpack` is inconvenient, embed the PNGs as base64 data URIs in one
Markdown file (`![alt](data:image/png;base64,...)`). It is fully self-contained
but heavier, and not every editor renders data-URI images — the `.textpack` is
the more reliable bundle for Ulysses.

## Gotchas

- **Reflow first.** Ragged lines / vertical gaps are a hard-wrapping artifact, not
  a Ulysses/Ghost bug.
- **Render mermaid.** Neither Ulysses nor Ghost renders `mermaid` blocks; ship PNGs.
- **White background, 2× scale** for crisp, paste-anywhere images.
- **iOS:** relative image paths in pasted Markdown do not resolve — only the
  bundled `.textpack` (or base64) shows images inline.
- **Commit the `.textpack` in `dist/`.** Keep the built `.textpack` next to the
  post under `docs/blog/<name>/dist/` (mirroring `docs/book/dist/`), so each
  release's ready-to-import bundle is versioned with the post. Commit only the
  `.textpack`, not the unzipped `.textbundle/`. (It re-bundles the diagram PNGs,
  which is an accepted, small duplication.) Don't commit a base64 fallback `.md`.

## Relation to releases

Each release ships a blog post at `docs/blog/<name>/post.md` with diagrams under
`diagrams/`. This guide is the last-mile step to hand that post to a
writing/publishing app, and `docs/book/PUBLISH.md` makes a `.textpack` a required
deliverable for every post.
