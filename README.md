# Mackie DC16 als REAPER-Controller

Die Bridge `dc16_bridge.py` lässt ein **Mackie DC16** (Fader-Controller, normalerweise Bedienoberfläche
für den DL32R) mit **REAPER** zusammenarbeiten – unter Linux und Windows, nur Python 3, keine Zusatzpakete.

Das Prinzip: Der DC16 hält sich für den Client eines DL32R-Mixers. Die Bridge **spielt den DL32R** (Discovery,
Handshake, Zustandsdump) und übersetzt alle Bedienungen zwischen dem Mandolin-Protokoll des Pults und
**OSC** von/zu REAPER.

```
 DC16  <--- Ethernet (UDP 61000/61001, TCP 50001) --->  dc16_bridge.py  <--- OSC (UDP 8000/9000) --->  REAPER
                                                              ^
                                       dc16_colors.txt  <-----+----  dc16_colors.lua (Spurfarben, Projektwechsel)
                                       dc16_state.json         (zuletzt bekannter REAPER-Zustand)
```

## Was funktioniert

| Funktion | Richtung | Anmerkung |
|---|---|---|
| Fader (motorisiert), Mute, Solo | beide | 32 Strips pro Seite |
| Select | beide | exklusiv (Aktion 40297 „Unselect all“, sonst addiert REAPER die Auswahl) |
| Master-Fader | beide | über Pattern `MASTER_VOLUME f/master/volume/db` |
| Metering (LED-Balken, Master L/R) | REAPER → DC16 | aus REAPER-VU, auf dB skaliert |
| Kanalnamen (Displays) | REAPER → DC16 | max. 6 ASCII-Zeichen |
| Kanalfarben | REAPER → DC16 | auf die 16 Pultfarben + Weiß/None gerundet, per Lua-Script |
| Seiten | beide | jeder Layer LR/A1–A14/FX1–FX4 = weitere 32 Spuren (bis Spur 608) |
| Projektwechsel | – | Lua meldet Wechsel, Bridge synchronisiert neu |

**Nicht umgesetzt:** Master-Mute (kein OSC-Pattern in REAPER), Layer Sub/VCA/M, Encoder-Modi (EQ/GEQ/Dyn/FX),
Gruppen-Tasten, Gain-Reduction-Anzeige, 17. Fader in den Aux-Layern.

## Dateien

| Datei | Zweck |
|---|---|
| `dc16_bridge.py` | die Bridge (Hauptprogramm) |
| `dc16_profile.json` | **aus dem Mitschnitt erzeugt**: Handshake, Antworten, Zustandsdump, Discovery-Paket, Meter-Ruhewerte. Unbedingt sichern! |
| `dc16_colors.lua` | ReaScript: schreibt Spurfarben + Projektkennung nach `<REAPER-Ressourcenpfad>/dc16_colors.txt` |
| `make_lean_osc.py` | erzeugt aus einem ReaperOSC-File eine **schlanke Pattern-Config** (`DC16lean.ReaperOSC`) |
| `dc16_state.json` | wird automatisch angelegt: letzter REAPER-Zustand, gelernte Skalen, Namen |
| `mandolin_*.py`, `fake_dl32r.py` | Analyse-Werkzeuge/Vorstufen aus dem Reverse Engineering (für Betrieb nicht nötig) |

## Einrichtung

### 1. Netzwerk
DC16 und Rechner direkt per Ethernet verbinden (oder gemeinsames Netz). Der DC16 sucht per Broadcast nach
einem DL32R. Dem Rechner-Adapter eine feste Adresse im DC16-Netz geben, z. B. `169.254.50.1/16`
(Link-Local). Diese IP kommt als `--ip` an die Bridge. Der DL32R darf **nicht** gleichzeitig im Netz sein.

### 2. Profil erzeugen (einmalig, braucht `tshark`)
```
python3 dc16_bridge.py --export msgs.pkl dc16-aktion2.pcapng
```
`msgs.pkl` entsteht aus dem Mitschnitt einer echten DC16↔DL32R-Verbindung (`mandolin_parse.py`). Ergebnis:
`dc16_profile.json`. Die Datei funktioniert danach ohne tshark auch unter Windows.

### 3. REAPER konfigurieren
1. **Pattern config:** `make_lean_osc.py` erzeugt die schlanke Config. Sie muss Spuren auf **192** (oder dein
   Projektmaximum, Vielfaches von 32) begrenzen:
   ```
   python3 make_lean_osc.py <Default-Kopie>.ReaperOSC 192 DC16lean.ReaperOSC
   ```
   Ablegen im REAPER-Ordner `OSC/` (Flatpak: `~/.var/app/fm.reaper.Reaper/config/REAPER/OSC/`), dann in
   *Preferences → Control/OSC/web → Add → OSC* als Pattern config **DC16lean** wählen.
   Wichtig: Die Default-Config mit 608 Spuren löst beim Start einen Feedback-Flood aus, der alles
   minutenlang verzögert.
2. **OSC-Einstellungen:** *Local listen port* = **8000** (hierhin sendet die Bridge); *Device IP* `127.0.0.1` und
   *Device port* = **9000** (hierhin schickt REAPER sein Feedback, die Bridge hört darauf). Die Ports lassen sich
   mit `--reaper-port` und `--listen-port` ändern. „Max packets per second“ ≥ 3000.
3. **Patterns, die gebraucht werden:** `TRACK_VOLUME f/track/@/volume/db`, `MASTER_VOLUME f/master/volume/db`,
   `TRACK_MUTE`, `TRACK_SOLO`, `TRACK_SELECT`, `TRACK_NAME`, `TRACK_VU`, `MASTER_VU_L/R`. Die Lean-Config enthält alle.
4. **Farben:** `dc16_colors.lua` in REAPER laden (Actions → Show action list → Load ReaScript) und ausführen
   (am besten als Startup-Action). Es schreibt `dc16_colors.txt` in den REAPER-Ressourcenpfad.

### 4. Starten
```
python3 dc16_bridge.py --ip 169.254.50.1 --color-file ~/.var/app/fm.reaper.Reaper/config/REAPER/dc16_colors.txt
```
Empfehlung: in ein `start-dc16.sh` / `.bat` legen, damit `--color-file` nie fehlt (ohne bleiben die Farben aus).

Danach DC16 einschalten. Im Log erscheinen *Discovery beantwortet → DC16 verbunden → Zustandsdump gesendet →
Seite 0 … geschrieben*. Reihenfolge beim Start egal; die Bridge wartet, bis der DC16 sich meldet.

## Windows-Besonderheiten

- **Netzwerkprofil auf „Privat“ stellen.** Ist das Netz als „Öffentlich“ eingestuft, blockiert die Windows-Firewall auch im LAN
  eingehende Verbindungen: Der DC16 bekommt seine Discovery-Antwort, kann sich aber nie per TCP verbinden, und die Bridge
  zeigt nichts. (Einstellungen → Netzwerk und Internet → Ethernet → Netzwerkprofiltyp.)
- **Firewall-Regeln** (als Administrator), gelten für alle Profile:
  ```
  netsh advfirewall firewall add rule name="DC16 Bridge TCP" dir=in action=allow protocol=TCP localport=50001 profile=any
  netsh advfirewall firewall add rule name="DC16 Bridge UDP" dir=in action=allow protocol=UDP localport=61000 profile=any
  ```
- **`--ip` = Adresse des LAN-Adapters** (`ipconfig`). Das Discovery-Paket trägt diese Adresse, der DC16 verbindet sich dorthin. Bei
  mehreren Adaptern (WLAN, VM-Bridge) die des Netzes nehmen, in dem der DC16 hängt. Die Bridge warnt beim Start, wenn die IP
  zu keinem Adapter gehört.
- **DHCP-Netz:** funktioniert, solange Rechner und DC16 im selben Subnetz/VLAN liegen (Discovery ist ein Broadcast). Mit
  DHCP-Reservierung (MAC-Bindung) bleibt `--ip` stabil; ohne feste Adresse ändert sie sich irgendwann und die Bridge-Option muss angepasst werden.
- **Log-Hinweis:** Erscheint nach „Discovery … beantwortet“ keine Zeile „TCP-Verbindung vom DC16 … angenommen“, liegt es an
  Firewall oder falscher `--ip`.
- **Start-Script** (`start-dc16.bat`), damit `--color-file` und `--ip` nie fehlen:
  ```
  @echo off
  python dc16_bridge.py --ip 192.168.1.50 --color-file "%APPDATA%\REAPER\dc16_colors.txt"
  pause
  ```

## Optionen

| Option | Bedeutung |
|---|---|
| `--ip` | IP des Rechners am DC16-Netz (Pflicht) |
| `--profile` | Profil-Datei (Standard `dc16_profile.json`) |
| `--reaper-host/-port` | Ziel der OSC-Befehle (127.0.0.1:8000) |
| `--listen-port` | Port, auf dem REAPER-Feedback ankommt (9000) |
| `--track-offset N` | DC16-Strip 1 = REAPER-Spur 1+N |
| `--color-file` | Datei von `dc16_colors.lua` |
| `--no-pages` | Layer nicht als Seiten nutzen (nur Spuren 1–32) |
| `--no-osc` | ohne REAPER (nur Test) |
| `--export PKL PCAP` | Profil erzeugen (siehe oben) |
| `--probe-tables`, `--tabletext` | Experimente der Analyse, im Normalbetrieb nicht nötig |

## Seiten (Layer = 32 weitere Spuren)

Das Pult hat nur 32 Strips. Die Layer-Tasten nutzen wir als **Seitenwahl**:

| Layer am Pult | REAPER-Spuren |
|---|---|
| LR | 1–32 |
| A1 | 33–64 |
| A2 | 65–96 |
| … | … |
| A14 | 417–448 |
| FX1–FX4 | 449–576 |

(Seite = Layer-Nummer, Spur = 32·Seite + Strip, plus `--track-offset`.) Intern liegt dahinter pro Layer ein anderer
Fader-Offset im Kanal-Record (`FADER_OFF`). Beim Start steht das Pult immer auf LR. Layer Sub/VCA/M haben noch keine Belegung
und werden im Log als „keine Seitenzuordnung“ gemeldet. Mit der Lean-Config und 192 Spuren sind Seiten 0–5 belegt.

## Konsole

Befehle in das Terminal tippen, in dem die Bridge läuft (Kanalnummern = Strip 1–32 der aktuellen Seite):

| Befehl | Wirkung |
|---|---|
| `f <ch> <dB>` | Fader fahren (Test) |
| `m <ch> <0/1>`, `s <ch> <0/1>` | Mute / Solo |
| `name <strip> <text>` | Display-Name setzen |
| `colortest <ch>`, `color <ch> <index>` | Pultfarben (0–15 bunt, 16 weiß, 17 none) |
| `stat` | Status: Seite, Verbindung, Meter-Gruppen, OSC-Zähler |
| `refresh` | aktuelle Seite neu auf den DC16 schreiben |
| `page <layer>` | Seite von Hand wechseln |
| `vm <spur> <dB>`, `vclear` | VU-Skala messen/zurücksetzen |
| `cal [spur]` | Fader-Skala lernen (meist unnötig) |
| `mt <ch/0=Master> <dB>` | Meter-Testwert setzen |
| `raw <fmt-hex> <idx> <wert>` | beliebigen Wert ins Zustandsfeld schreiben (Entwicklung) |
| `probe <fmt> <von> <bis>` | Indexbereich mit Text füllen (Entwicklung) |
| `flag <0/8>` | Flag für `push` (Entwicklung) |
| `v` | ausführliches Log (zeigt auch `WRITE (unbekannt)`) |
| `q` | beenden |

## Fehlersuche

| Symptom | Ursache / Abhilfe |
|---|---|
| Pult findet keinen Mixer | `--ip` falsch, Firewall (UDP 61000, TCP 50001), echter DL32R noch im Netz |
| Verbindung wird nach ~2 s getrennt | Handshake-Reihenfolge verletzt – Profil neu erzeugen; sonst mit `v` und Mitschnitt vergleichen |
| Alles beim Start sehr langsam | Default-OSC-Pattern mit 608 Spuren aktiv → `DC16lean` laden |
| Nur die ersten 8 Fader bewegen sich | falsche Pattern-Config / `DEVICE_TRACK_COUNT` zu klein |
| Mute/Solo gehen nur in eine Richtung | OSC-Pattern ist nicht boolesch; Bridge schickt 0/1 – Pattern prüfen |
| Master-Fader bewegt sich nicht beim Start | `dc16_state.json` fehlt/leer – einmal in REAPER bewegen, danach wird gespeichert |
| Meter leer / zu hoch | `stat` (kommen VU-Werte?), `vm` zum Nachmessen |
| Farben fehlen | Bridge ohne `--color-file` gestartet, oder `dc16_colors.lua` läuft nicht |
| Bei Projektwechsel bleiben Daten alt | Lua-Script muss laufen (liefert Projektkennung); `refresh` auf der Konsole |
| Selektion „addiert“, Fader verlinken | `/action/40297` nicht erreichbar – Action-Pattern in der OSC-Config prüfen |

## Protokoll (Mandolin) – für Weiterentwicklung

**Discovery:** DC16 sendet alle ~2 s einen Broadcast (UDP 61001 → 61000). Wir antworten mit dem aufgezeichneten
Paket, dessen Bytes 12–15 die eigene IP tragen (little-endian). **Verbindung:** TCP 50001, der DC16 ist Client.

**Frame** (alles Big-Endian): `0xAB | ident | Länge in Wörtern (16 Bit) | flag | cmd | ~Summe(Kopf) (16 Bit)`,
bei Nutzdaten danach `Nutzdaten | ~Summe(Nutzdaten) (32 Bit)`. Flags: 0 Anfrage, 1 Antwort, 8 Benachrichtigung, 9 Antwort darauf.

**Handshake:** DC16 `cmd 06` → Antwort, dann senden wir nacheinander `03`, `02`, `0e` (jeweils nach der Antwort des DC16);
DC16 fragt `04`, dann `cmd 06` mit Nutzdaten `00000006` → wir senden den **Zustandsdump** (aufgezeichnet, mit Fixes). Danach
Herzschlag `cmd 01` alle 4 s.

**Zustandsfeld:** `cmd 0x13` mit `[Index][Format][Werte]`:
- Format `0x500` – großes gemischtes Feld (Float/Int). Kanal-Record **132 Wörter** ab Index **41**: +5 Farbe, +7 Mute, +8 Fader LR (dB −120…+10),
  +9 Pan, +20 Gain, +23 HPF, Aux-Sendfader +58+3(k−1) (A1–A14), FX-Send +100+2(k−1). Master-Fader **5995**, Master-Mute **5996**.
- Format `0x200` – kleines Int-Feld: Solo-Index 24…55 (23+Strip), Select Index **0x96** (Wert = Strip 1–32), Layer Index **0x9e**
  (0 LR, 1–14 A, 15–18 FX, 19–24 Sub, 25–30 VCA, 31–36 M).
- Hi-Nibble des Formats: 0 Block, 1 Meter, 2 Paare `[Index][Wert]`.

**Namen:** `cmd 0x18`, Tabelle 0x59 (89 Einträge, NUL-getrennte Strings, je 4-Byte-Gruppe umgedreht). Im Dump als Block, live als
`[Eintrag][0x00010500][Name]`. Eintrag n = Kanal n, Aux n = 51+n.

**Meter:** DC16 abonniert Gruppen (`cmd 0x16`, Gruppe + Meter-ID-Liste, wir antworten flag 9), startet den Push mit `cmd 0x15`
(Intervall = Wert>>16 ms). Wir senden `cmd 0x13` flag 8 `[Gruppe][0x10000100][Floats]` etwa 25/s. Meter-IDs: Kanal n Pegel **34+7(n−1)**
(daneben +2 = 60.0 und +5 = 0.0 im Ruhezustand – unbekannt, evtl. Dynamik/GR), Master L/R **310/311**, Bus-Master 318+4(k−1).
Pegel sind dB-Floats (−120 = still).

**Neue Funktion finden (Reverse Engineering):** Bridge mit `v` starten, am Pult bedienen und nach `WRITE (unbekannt) fmt=… idx=…` suchen.
Dort steht Feldtyp und Index. Für DC16-Anzeigen (Schreiben auf das Pult) hilft ein Mitschnitt der echten DL32R-App (WLAN-Access-Point an den
DL32R, `tshark`), während man am Gerät dieselbe Funktion bedient, und dann Index-Änderungen vergleichen (`mandolin_*.py`).

## Hinweise zum Code

- Alles liegt in einer Datei; die Kopfzeile von `dc16_bridge.py` zeigt die Gliederung.
- `state` = was der DC16 gerade zeigt, `rstate` = letzter REAPER-Zustand (wird gespeichert); Schlüssel ist die **Spurnummer**, nicht der Strip.
- `quiet_until` verhindert, dass das OSC-Echo einer Pultbedienung den Fader sofort zurückfährt.
- Der Dump aus dem Profil wird beim Senden zweifach verändert: Namenstabelle wird durch die aktuelle ersetzt, Layer-Wort wird auf LR gesetzt.
- VU: REAPER liefert 0–1, linear in dB, gemessen etwa `dB ≈ 68·x − 62` (Startwerte im Code); mit mindestens 3 Messpunkten (`vm`) fittet die Bridge nach.
- Farben: 16 Palettenfarben (RGB in `PALETTE`), Graustufen → Weiß (hell) bzw. None.
