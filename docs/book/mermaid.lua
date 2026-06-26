-- Pandoc Lua filter: render fenced ```mermaid code blocks to PNG via the Mermaid
-- CLI (mmdc) at build time, so the book source can carry Mermaid directly while
-- Pandoc (which can't render Mermaid) embeds an image in the EPUB/PDF/MOBI.
--
-- Rendered PNGs go in $MERMAID_OUT (an absolute dir created by build.sh). If a
-- render fails, the original code block is left untouched and a warning printed.

local out_dir = os.getenv("MERMAID_OUT") or "."
local puppeteer = os.getenv("MERMAID_PUPPETEER") -- optional puppeteer config path
local count = 0

local function shquote(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

function CodeBlock(block)
  if not block.classes:includes("mermaid") then
    return nil
  end

  count = count + 1
  local stem = out_dir .. "/diagram-" .. count
  local mmd = stem .. ".mmd"
  local png = stem .. ".png"

  local fh = io.open(mmd, "w")
  if not fh then
    io.stderr:write("mermaid.lua: cannot write " .. mmd .. "\n")
    return nil
  end
  fh:write(block.text)
  fh:close()

  local pflag = ""
  if puppeteer and puppeteer ~= "" then
    pflag = " -p " .. shquote(puppeteer)
  end
  -- White background, 2x scale: crisp and safe on light or dark backgrounds.
  local cmd = "mmdc -i " .. shquote(mmd) .. " -o " .. shquote(png)
    .. " -b white -s 2" .. pflag .. " >/dev/null 2>&1"

  if not os.execute(cmd) then
    io.stderr:write("mermaid.lua: mmdc failed for diagram " .. count .. "\n")
    return nil
  end

  return pandoc.Para({ pandoc.Image({}, png) })
end
