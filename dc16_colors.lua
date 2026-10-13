-- dc16_colors.lua: schreibt die Spurfarben (Spur 1..608) fuer die DC16-Bruecke in eine Textdatei.
-- Laeuft im Hintergrund und aktualisiert die Datei nur bei Aenderungen.
-- Datei: <REAPER-Resource-Ordner>/dc16_colors.txt   (Pfad im Bruecken-Aufruf mit --color-file angeben)
local sep = package.config:sub(1, 1)
local path = reaper.GetResourcePath() .. sep .. "dc16_colors.txt"
local last, nextcheck = "", 0

local function scan()
  local out = {}
  local n = math.min(reaper.CountTracks(0), 608)
  for i = 0, n - 1 do
    local tr = reaper.GetTrack(0, i)
    local c = reaper.GetTrackColor(tr)
    if c ~= 0 then
      local r, g, b = reaper.ColorFromNative(c)
      out[#out + 1] = string.format("%d %d %d %d", i + 1, r, g, b)
    else
      out[#out + 1] = string.format("%d none", i + 1)
    end
  end
  local s = table.concat(out, "\n") .. "\n"
  if s ~= last then
    local f = io.open(path, "w")
    if f then f:write(s); f:close(); last = s end
  end
end

local function loop()
  local t = reaper.time_precise()
  if t >= nextcheck then
    nextcheck = t + 0.3
    scan()
  end
  reaper.defer(loop)
end

reaper.ShowConsoleMsg("dc16_colors.lua schreibt nach: " .. path .. "\n")
loop()
