#!/usr/bin/env python3
"""Mackie DC16 <-> REAPER (OSC) Bruecke mit eingebautem Fake-DL32R.

Laeuft unter Linux und Windows (nur Python 3, keine Zusatzpakete).

Einmalig (auf dem Rechner mit tshark, also deinem Fedora) das Profil erzeugen:
  python3 dc16_bridge.py --export msgs.pkl dc16-aktion2.pcapng
  -> schreibt dc16_profile.json (Boot-Handshake, Antworten, Discovery-Paket)
Diese Datei kannst du auf den Windows-Rechner mitnehmen.

Betrieb:
  python3 dc16_bridge.py --ip 169.254.50.1
    --ip            IP deines Rechners am DC16-Netz (169.254.x.x, Windows: Adapter-IP)
    --reaper-host   (127.0.0.1)  --reaper-port 8000   REAPER hoert hier
    --listen-port   9000                              REAPER sendet Feedback hierher
    --track-offset  0   (DC16-Kanal 1 = REAPER-Spur 1+offset)

Weitere Optionen: --color-file PFAD (von dc16_colors.lua), --no-pages, --no-osc, --profile DATEI.

Konsole (zum Testen): f <ch> <dB> | m <ch> <0|1> | s <ch> <0|1> | raw <fmt> <idx> <wert> |
                      colortest <ch> | color <ch> <index> | stat | refresh | page <layer> | name <strip> <text> | probe <fmt> <von> <bis> | vm <spur> <dB> | vclear | cal [spur] | mt <ch|0=Master> <dB> | flag <0|8> | v (mehr Log an/aus) | q

AUFBAU DER DATEI (von oben nach unten) - Details und Protokollbeschreibung in README.md
  1. Argumente, OSC-Adressen
  2. Profil-Export (--export): liest den Mitschnitt, erzeugt dc16_profile.json
  3. Protokoll-Grundlagen: frame(), Zustandsvariablen, Farben, Seiten (Layer = 32 Spuren)
  4. Zustand speichern/laden (dc16_state.json), Namen, Farben, Seiten schreiben
  5. OSC-Minimalimplementierung und REAPER -> DC16 (from_reaper)
  6. DC16 -> REAPER (on_write) und Meter (meter_push)
  7. Protokoll-Handshake (handle/feed), Konsole, Hauptschleife

Grundprinzip: Der DC16 haelt sich fuer einen Mixer-Client und verbindet sich mit einem DL32R. Wir
spielen den DL32R: Sein Zustand ist ein grosses Feld aus 32-Bit-Woertern (Index -> Wert). Der DC16
schreibt Aenderungen (cmd 0x13 flag 8); wir schreiben REAPER-Aenderungen mit demselben Befehl zurueck.
"""
import argparse, json, os, re, queue, select, socket, struct, subprocess, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--export", nargs=2, metavar=("PKL", "PCAP"))
ap.add_argument("--ip")
ap.add_argument("--profile", default="dc16_profile.json")
ap.add_argument("--reaper-host", default="127.0.0.1")
ap.add_argument("--reaper-port", type=int, default=8000)
ap.add_argument("--listen-port", type=int, default=9000)
ap.add_argument("--track-offset", type=int, default=0)
ap.add_argument("--no-osc", action="store_true")
ap.add_argument("--no-pages", action="store_true",
                help="Layer nicht als Seiten zu je 32 Spuren nutzen (nur LR = Spuren 1-32)")
ap.add_argument("--color-file", help="Von dc16_colors.lua geschriebene Datei mit den Spurfarben")
ap.add_argument("--probe-tables", action="store_true",
                help="Tabellen cmd 0x0e (Typ 9/10) mit Testtexten fuellen, um das Namensfeld zu finden")
ap.add_argument("--tabletext", default="BE", choices=["BE", "LE"], help="Byte-Reihenfolge der Testtexte")
args = ap.parse_args()

# OSC-Adressen (REAPER-Pattern-Config, siehe DC16.ReaperOSC). {n} = Spurnummer.
ADDR = {
    "vol": "/track/{n}/volume/db",
    "mute": "/track/{n}/mute",
    "solo": "/track/{n}/solo",
    "sel": "/track/{n}/select",
    "mvol": "/master/volume/db",
    "mmute": "/master/mute",
    "unsel": "/action/40297",          # REAPER-Aktion "Track: Unselect all tracks"
}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- Profil-Export
if args.export:
    import pickle
    pkl, pcap = args.export
    msgs = sorted(pickle.load(open(pkl, "rb")), key=lambda m: m[0])
    t_sub = min(m[0] for m in msgs if m[1] == "DC16" and m[4] == 0x16 and m[3] == 8)
    boot = [m for m in msgs if m[1] == "DL32R" and m[3] == 0 and m[4] != 0x01 and m[0] < t_sub]
    first13 = next(i for i, m in enumerate(boot) if m[4] == 0x13)
    rep, fb = [], {}
    seen = set()
    dc_req = [m for m in msgs if m[1] == "DC16" and m[3] == 0 and m[4] != 0x01]
    dl_rep = [m for m in msgs if m[1] == "DL32R" and m[3] == 1]
    for r in dc_req:
        for a in dl_rep:
            if a[2] == r[2] and a[4] == r[4] and 0 <= a[0] - r[0] < 0.5:
                if (r[4], r[7]) not in seen:
                    seen.add((r[4], r[7]))
                    rep.append([r[4], r[7].hex(), a[7].hex()])
                fb.setdefault(str(r[4]), a[7].hex())
                break
    out = subprocess.check_output(
        ["tshark", "-r", pcap, "-Y", "udp.srcport==61000 && udp.dstport==61001",
         "-T", "fields", "-e", "udp.payload"], text=True).split()
    if not out:
        sys.exit("Keine Discovery-Antwort im Mitschnitt")
    groups, samples = {}, {}
    for m in msgs:
        if m[1] == "DC16" and m[3] == 8 and m[4] == 0x16:
            w = struct.unpack(">%dI" % (len(m[7]) // 4), m[7])
            if w[0] == 0xFFFFFFFF:
                groups.clear()
            else:
                groups[w[0]] = list(w[1:])
        elif m[1] == "DL32R" and m[3] == 8 and m[4] == 0x13 and len(m[7]) >= 12:
            w = struct.unpack(">%dI" % (len(m[7]) // 4), m[7])
            if w[1] >> 28 == 1 and w[0] in groups and len(groups[w[0]]) == len(w) - 2:
                for i, v in zip(groups[w[0]], w[2:]):
                    samples.setdefault(i, []).append(struct.unpack(">f", struct.pack(">I", v))[0])
    idle = {}
    for i, v in samples.items():
        v.sort()
        idle[str(i)] = v[len(v) // 2]
    prof = {"meter_idle": idle, "boot_a": [[m[4], m[7].hex()] for m in boot[:first13]],
            "boot_b": [[m[4], m[7].hex()] for m in boot[first13:]],
            "replies": rep, "fallback": fb, "disc": out[0].replace(":", "")}
    json.dump(prof, open("dc16_profile.json", "w"))
    print("dc16_profile.json geschrieben:", len(prof["boot_a"]), "+", len(prof["boot_b"]),
          "Boot-Anfragen,", len(rep), "Antworten")
    sys.exit(0)

if not args.ip:
    sys.exit("--ip fehlt (oder --export benutzen)")
P = json.load(open(args.profile))
boot_a = [(c, bytes.fromhex(h)) for c, h in P["boot_a"]]
boot_b = [(c, bytes.fromhex(h)) for c, h in P["boot_b"]]
replies = {(c, bytes.fromhex(q)): bytes.fromhex(r) for c, q, r in P["replies"]}
fallback = {int(c): bytes.fromhex(r) for c, r in P["fallback"].items()}
if args.probe_tables:
    for key in list(replies):
        if key[0] == 0x0e and len(key[1]) == 4 and struct.unpack(">I", key[1])[0] in (9, 10):
            tid = struct.unpack(">I", key[1])[0]
            old = replies[key]
            words = len(old) // 4
            out = old[:8]
            for k in range(words - 2):
                t = (f"{k:02d}" + ("A" if tid == 10 else "B")).encode()[:3] + b"\0"
                out += t if args.tabletext == "BE" else t[::-1]
            replies[key] = out
            print(f"probe-tables: Tabelle {tid}: {words - 2} Eintraege mit Testtext", flush=True)
meter_idle = {int(k): v for k, v in P.get("meter_idle", {}).items()}
disc = bytes.fromhex(P["disc"])
disc = disc[:12] + bytes(reversed(socket.inet_aton(args.ip))) + disc[16:]


# ---------------------------------------------------------------- Mandolin-Protokoll
def frame(ident, flag, cmd, pl=b""):
    """Mandolin-Frame bauen: 0xAB | ident | Laenge in 32-Bit-Woertern (BE16) | flag | cmd | ~Summe(Kopf)
    (16 Bit), danach Nutzdaten + ~Summe(Nutzdaten) (32 Bit), falls Nutzdaten vorhanden.
    flag: 0 Anfrage, 1 Antwort, 8 Benachrichtigung, 9 Antwort darauf. Alle Zahlen Big-Endian."""
    h = bytes([0xAB, ident]) + struct.pack(">H", len(pl) // 4) + bytes([flag, cmd])
    h += struct.pack(">H", ~sum(h) & 0xFFFF)
    if pl:
        h += pl + struct.pack(">I", ~sum(pl) & 0xFFFFFFFF)
    return h


NCH = 32                               # Strips (Fader) des DC16 pro Seite
# Kanal-Records im grossen Zustandsfeld (fmt 0x500): Kanal n beginnt bei Index BASE + REC*(n-1).
# Offsets im Record: +5 Farbe, +7 Mute, +8 Fader LR, +58+3(k-1) Aux-Sendfader Ak, +100+2(k-1) FX-Send.
REC, BASE = 132, 41
IDX_MASTER_FADER, IDX_MASTER_MUTE = 5995, 5996
S = {"verbose": False, "flag": 0}      # Verbindungs-/Protokollzustand (siehe reset())
# state = was der DC16 gerade anzeigt; rstate = letzter bekannter REAPER-Zustand (wird gespeichert).
# Schluessel: Spurnummer T (1..608), nicht Strip-Nummer.
state = {"fader": {}, "mute": {}, "solo": {}, "color": {}, "sel": None, "mfader": None, "mmute": None}
rstate = {"fader": {}, "mute": {}, "solo": {}, "color": {}, "sel": None, "mfader": None, "mmute": None}
# Farbpalette des Pults (Index -> RGB), nach der App-Palette von links oben nach rechts unten.
# Index 16 = Weiss, Index 17 = None (16/17 mit "colortest" pruefen!)
PALETTE = {0: (233, 30, 99), 1: (240, 98, 98), 2: (238, 52, 36), 3: (240, 90, 43),
           4: (247, 166, 50), 5: (255, 200, 15), 6: (245, 235, 60), 7: (160, 205, 90),
           8: (80, 183, 110), 9: (134, 205, 168), 10: (35, 187, 172), 11: (100, 205, 228),
           12: (28, 171, 220), 13: (44, 112, 184), 14: (165, 120, 180), 15: (133, 76, 158)}
WHITE_IDX, NONE_IDX = 16, 17

# Seiten: jeder Layer des DC16 zeigt 32 weitere REAPER-Spuren (LR = 1-32, A1 = 33-64, ...).
# Bus-Nummer (Schreibzugriff 0x200/0x9e) -> Offset des Faders im Kanal-Record
FADER_OFF = {0: 8}
FADER_OFF.update({b: 58 + 3 * (b - 1) for b in range(1, 15)})        # Aux A1..A14
FADER_OFF.update({b: 100 + 2 * (b - 15) for b in range(15, 19)})     # FX1..FX4
MAXPAGE = 18
PAGE = {"b": 0}                       # Der Dump wird beim Senden auf Layer LR (0) gesetzt


def cur_page():
    """Aktuelle Seite (0 = LR = Spuren 1-32, 1 = A1 = 33-64, ...) oder None bei Layern ohne Zuordnung."""
    if args.no_pages:
        return 0
    return PAGE["b"] if PAGE["b"] in FADER_OFF else None


def max_track():
    return NCH if args.no_pages else NCH * (MAXPAGE + 1)


def T_of(n):
    """Strip n (1..32) der aktuellen Seite -> REAPER-Spurnummer"""
    p = cur_page()
    return None if p is None else p * NCH + n


def strip_of(T):
    """REAPER-Spurnummer -> (Seite, Strip 1..32)"""
    p, n = divmod(T - 1, NCH)
    return p, n + 1


STATE_FILE = "dc16_state.json"
dirty = {"t": 0.0}
names = {}                             # Eintrag (1 = Kanal 1, 52 = Aux 1, ...) -> Name
NAME_TABLE = 89                        # Eintraege der Namenstabelle (cmd 0x18, Tabelle 0x59)
NAME_LEN = 6
vu_pts = []                            # Messpunkte (normalisierter VU-Wert, echte dB) fuer die Meter-Skala
vm = {"on": False}
VU_HOLD = 20.0                         # Sekunden ohne neuen REAPER-Wert, bis der Pegel auf -120 faellt
cal_pts = []                           # gelernte Paare (normalisiert, dB) der REAPER-Fader-Skala



def load_state():
    """Letzten bekannten REAPER-Zustand laden. Noetig, weil REAPER nur Aenderungen schickt: ohne diese
    Datei waeren Fader/Master nach einem Bridge-Neustart auf dem Pult auf Anfangswert."""
    try:
        d = json.load(open(STATE_FILE))
        for k in ("fader", "mute", "solo", "color"):
            rstate[k] = {int(n): v for n, v in d.get(k, {}).items()}
        for k in ("sel", "mfader", "mmute"):
            rstate[k] = d.get(k)
        cal_pts[:] = [tuple(p) for p in d.get("cal", [])]
        vu_pts[:] = [tuple(p) for p in d.get("vu", [])]
        names.update({int(k): v for k, v in d.get("names", {}).items()})
        log("letzten bekannten Zustand geladen:", STATE_FILE)
    except (OSError, ValueError):
        pass


def save_state():
    try:
        json.dump(dict({k: rstate[k] for k in rstate}, cal=cal_pts, vu=vu_pts, names=names), open(STATE_FILE, "w"))
    except OSError:
        pass


osc_stat = {"n": {}, "maxT": 0, "last": 0.0, "vu1": None}
refresh_due = {"t": 0.0}
quiet_until = {}                       # (art, n) -> Zeit; Feedback von REAPER dann ignorieren


def reset():
    """Verbindungszustand zuruecksetzen. conn = TCP-Socket, buf = Empfangspuffer, cnt = Frame-ID,
    qa = noch zu sendende Handshake-Anfragen, sentA/sentB = Handshake/Dump gesendet, grp/groups =
    Meter-Gruppen (cmd 0x16), iv = Meter-Intervall (s), ready_at = Zeitpunkt fuer sync_all()."""
    S.update(conn=None, buf=b"", cnt=0, qa=[], sentA=False, sentB=False, grp=None,
             iv=0.04, nxt_m=0.0, nxt_hb=0.0, groups={}, ready_at=0.0, synced=False)


reset()


def nid():
    S["cnt"] = S["cnt"] % 255 + 1
    return S["cnt"]


def drop(why=""):
    if S["conn"]:
        try:
            S["conn"].close()
        except OSError:
            pass
    log("DC16-Verbindung beendet", why)
    reset()


def send(data):
    if S["conn"]:
        try:
            S["conn"].sendall(data)
        except OSError as e:
            drop(f"(Sendefehler: {e})")


def send_req(flag, cmd, pl=b""):
    send(frame(nid(), flag, cmd, pl))


def push(fmt, idx, word):
    """Einen Wert ins Zustandsfeld des DC16 schreiben (cmd 0x13: [Index][Format][Wert]).
    fmt 0x500 = gemischtes Feld (Float/Int, grosser Block), 0x200 = kleines Int-Feld (Solo, Select, Layer)."""
    send_req(S["flag"], 0x13, struct.pack(">II", idx, fmt) + word)


def color_index(v):
    """REAPER-Farbe (Hex '#rrggbb', 'r g b' oder Zahl) -> naechste Palettenfarbe; 0 = keine Farbe"""
    try:
        if isinstance(v, str):
            t = v.strip()
            if t.startswith("#") and len(t) >= 7:
                r, g, b = int(t[1:3], 16), int(t[3:5], 16), int(t[5:7], 16)
            else:
                nums = [int(float(x)) for x in re.findall(r"-?\d+(?:\.\d+)?", t)]
                if len(nums) >= 3:
                    r, g, b = nums[:3]
                elif len(nums) == 1:
                    r, g, b = nums[0] & 255, (nums[0] >> 8) & 255, (nums[0] >> 16) & 255
                else:
                    return NONE_IDX
        else:
            iv = int(v)
            r, g, b = iv & 255, (iv >> 8) & 255, (iv >> 16) & 255
    except ValueError:
        return NONE_IDX
    if r == g == b == 0:
        return NONE_IDX                         # REAPER: keine Spurfarbe
    if max(r, g, b) - min(r, g, b) < 25:         # Grautoene
        return WHITE_IDX if max(r, g, b) > 150 else NONE_IDX
    return min(PALETTE, key=lambda i: sum((a - c) ** 2 for a, c in zip((r, g, b), PALETTE[i])))


color_mtime = {"t": 0.0, "next": 0.0}
project = {"tok": None}


def poll_colors(now):
    """Datei von dc16_colors.lua alle 0.5 s auf Aenderungen pruefen.
    Zeilen: 'P <projekt>|<anzahl>' (Projektkennung; Wechsel -> alte Spuren verwerfen, nach 2 s neu
    synchronisieren) und je Spur 'T r g b' oder 'T none'."""
    if not args.color_file or now < color_mtime["next"]:
        return
    color_mtime["next"] = now + 0.5
    try:
        mt = os.path.getmtime(args.color_file)
        if mt == color_mtime["t"]:
            return
        lines = open(args.color_file).read().splitlines()
    except OSError:
        return
    color_mtime["t"] = mt
    for ln in lines:
        if ln.startswith("P "):
            tok = ln[2:]
            if project["tok"] is not None and tok != project["tok"]:
                log(f"Projektwechsel erkannt: {tok}")
                try:
                    cnt = int(tok.rsplit("|", 1)[1])
                    for k in ("fader", "mute", "solo", "color"):
                        for t in [t for t in rstate[k] if t > cnt]:
                            del rstate[k][t]
                    for t in [t for t in names if t > cnt]:
                        del names[t]
                except (ValueError, IndexError):
                    pass
                refresh_due["t"] = now + 2.0
            project["tok"] = tok
            continue
        p = ln.split()
        try:
            n = int(p[0]) - args.track_offset
            ci = NONE_IDX if len(p) < 4 else color_index("%s %s %s" % tuple(p[1:4]))
        except (ValueError, IndexError):
            continue
        if 1 <= n <= max_track() and rstate["color"].get(n) != ci:
            rstate["color"][n] = ci
            dirty["t"] = dirty["t"] or now
            to_dc16("color", n, ci)
            if S["verbose"]:
                log(f"Farbe Spur {n + args.track_offset}: Index {ci}")


def clean_name(t):
    """Name fuers Display: nur ASCII (sonst '?'), maximal NAME_LEN Zeichen"""
    return t.encode("ascii", "replace").decode()[:NAME_LEN].replace("\0", "")


def le_words(b):
    """Textbytes auffuellen und jede 4-Byte-Gruppe umdrehen - so liegen Strings im Protokoll."""
    b = b + b"\0" * (-len(b) % 4)
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def name_table_payload():
    """Komplette Namenstabelle: NUL-getrennte Strings, Eintrag 1..89, je 4 Byte rueckwaerts (LE)"""
    base = (cur_page() or 0) * NCH
    raw = b"".join(clean_name(names.get(base + i, "") if i <= NCH else "").encode() + b"\0"
                   for i in range(1, NAME_TABLE + 1))
    return struct.pack(">II", 1, (NAME_TABLE << 16) | 0x500) + le_words(raw)


def send_name(n):
    """Name des Strips n (1..32) der aktuellen Seite an den DC16"""
    if S["conn"] and S["sentB"] and cur_page() is not None:
        nm = clean_name(names.get(cur_page() * NCH + n, ""))
        send_req(0, 0x18, struct.pack(">II", n, (1 << 16) | 0x500) + le_words(nm.encode() + b"\0"))


# Index im Zustandsfeld fuer Strip n der aktuellen Seite (Solo: Feld 0x200, ab Index 24)
def idx_fader(n): return BASE + REC * (n - 1) + FADER_OFF[cur_page()]
def idx_mute(n): return BASE + REC * (n - 1) + 7
def idx_color(n): return BASE + REC * (n - 1) + 5
def idx_solo(n): return 23 + n


def to_dc16(art, T, v):
    """Wert aus REAPER (Spur T) an den DC16 schicken, wenn verbunden, Dump durch und Spur sichtbar."""
    if not (S["conn"] and S["sentB"]):
        return
    if art in ("fader", "mute", "solo", "color", "sel"):
        p, n = strip_of(T)
        if cur_page() is None or p != cur_page():
            return
    if art == "fader":
        push(0x500, idx_fader(n), struct.pack(">f", max(-120.0, min(10.0, v))))
    elif art == "mute":
        push(0x500, idx_mute(n), struct.pack(">i", int(v)))
    elif art == "solo":
        push(0x200, idx_solo(n), struct.pack(">i", int(v)))
    elif art == "sel":
        push(0x200, 0x96, struct.pack(">i", n))
    elif art == "color":
        push(0x500, idx_color(n), struct.pack(">i", int(v)))
    elif art == "mfader":
        push(0x500, IDX_MASTER_FADER, struct.pack(">f", max(-120.0, min(10.0, v))))
    elif art == "mmute":
        push(0x500, IDX_MASTER_MUTE, struct.pack(">i", int(v)))


def refresh_page():
    """Alle 32 Strips der aktuellen Seite (Namen, Farben, Fader, Mute, Solo) neu schreiben."""
    p = cur_page()
    if p is None or not (S["conn"] and S["sentB"]):
        return
    for n in range(1, NCH + 1):
        T = p * NCH + n
        send_name(n)
        for art, key, dflt in (("color", "color", NONE_IDX), ("fader", "fader", -120.0),
                               ("mute", "mute", 0), ("solo", "solo", 0)):
            v = rstate[key].get(T, dflt)
            state[key][T] = v
            to_dc16(art, T, v)
    if rstate["sel"]:
        state["sel"] = rstate["sel"]
        to_dc16("sel", rstate["sel"], 0)
    log(f"Seite {p} (Spuren {p * NCH + 1}-{p * NCH + NCH}) an den DC16 geschrieben")


def set_page(b):
    """Layer-Wechsel am Pult (Bus-Nummer b aus Schreibzugriff 0x200/0x9e): Seite merken und neu schreiben.
    b: 0 LR, 1-14 A1-A14, 15-18 FX1-4, 19-24 Sub, 25-30 VCA, 31-36 M (ab 19 noch nicht belegt)."""
    if args.no_pages:
        return
    PAGE["b"] = b
    if b in FADER_OFF:
        refresh_page()
    else:
        log(f"Layer {b}: keine Seitenzuordnung (nur LR, A1-A14, FX1-FX4 sind belegt)")


def sync_all():
    """Nach dem Dump den REAPER-Zustand auf den DC16 schreiben."""
    refresh_page()
    if rstate["mfader"] is not None:
        to_dc16("mfader", 0, rstate["mfader"])
    if rstate["mmute"] is not None:
        to_dc16("mmute", 0, rstate["mmute"])


load_state()


# ---------------------------------------------------------------- OSC (minimal)
def osc_pad(b):
    return b + b"\0" * (4 - len(b) % 4)


def osc_msg(addr, v):
    if isinstance(v, bool):
        return osc_pad(addr.encode()) + osc_pad(b"," + (b"T" if v else b"F"))
    if isinstance(v, int):
        return osc_pad(addr.encode()) + osc_pad(b",i") + struct.pack(">i", v)
    return osc_pad(addr.encode()) + osc_pad(b",f") + struct.pack(">f", v)


def osc_parse(d):
    """OSC-Paket (auch Bundle) -> Liste (adresse, erster Wert). Typen f, i, s, T, F; T/F werden 1/0."""
    if d.startswith(b"#bundle"):
        out, o = [], 16
        while o + 4 <= len(d):
            n = struct.unpack(">i", d[o:o + 4])[0]
            out += osc_parse(d[o + 4:o + 4 + n])
            o += 4 + n
        return out
    try:
        e = d.index(b"\0")
        addr = d[:e].decode()
        o = (e + 4) & ~3
        e = d.index(b"\0", o)
        tags = d[o + 1:e].decode()
        o = (e + 4) & ~3
        val = None
        for t in tags:
            if t == "f":
                val = struct.unpack(">f", d[o:o + 4])[0]
                break
            if t == "i":
                val = struct.unpack(">i", d[o:o + 4])[0]
                break
            if t == "s":
                e2 = d.index(b"\0", o)
                val = d[o:e2].decode("utf-8", "replace")
                break
            if t == "T":
                val = 1
                break
            if t == "F":
                val = 0
                break
        return [(addr, val)] if val is not None else []
    except (ValueError, struct.error, UnicodeDecodeError):
        return []


osc_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
osc_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if not args.no_osc:
    osc_in.bind(("", args.listen_port))


def to_reaper(key, v, n=None):
    """Wert per OSC an REAPER (Schluessel aus ADDR, n = Spurnummer). Mute/Solo/Select als Zahl 0/1."""
    if args.no_osc:
        return
    a = ADDR[key].format(n=(n + args.track_offset) if n is not None else 0)
    if key in ("mute", "solo", "sel", "mmute"):
        v = 1.0 if v else 0.0
    osc_out.sendto(osc_msg(a, v), (args.reaper_host, args.reaper_port))


SEED = [(0.0, -120.0), (0.716, 0.0), (1.0, 12.0)]   # grobe Startwerte, werden durch gelernte Paare ersetzt
last_db, last_norm = {}, {}
live_t = {}                            # Meter-ID -> Zeit des letzten REAPER-Werts
cal = {"on": False}
ct = {"on": False}


# Fader-Kalibrierung (Konsole: cal) - Relikt aus der Anfangszeit, normalisierte Fader-Werte -> dB.
# Wird nur noch durch learn()/cal_pts gespeist; die dB-Pattern von REAPER machen sie meist unnoetig.
def norm_to_db(x):
    pts = sorted(set(cal_pts)) if len(cal_pts) >= 4 else sorted(set(cal_pts) | set(SEED))
    if x <= pts[0][0]:
        return -120.0
    for (x0, d0), (x1, d1) in zip(pts, pts[1:]):
        if x <= x1:
            return d0 + (d1 - d0) * (x - x0) / (x1 - x0) if x1 > x0 else d1
    return pts[-1][1]


def vu_to_db(x):
    """REAPER-VU ist linear in dB: dB = a*x + b (gemessen: a = 68, b = -62, 0..1 = -62..+6 dB).
    Mit >= 3 eigenen Messpunkten (vm) wird per Ausgleichsgerade nachgefittet."""
    if x <= 0.002:
        return -120.0
    a, b = 68.0, -62.0
    if len(vu_pts) >= 3:
        n = len(vu_pts)
        sx = sum(p[0] for p in vu_pts)
        sy = sum(p[1] for p in vu_pts)
        sxx = sum(p[0] * p[0] for p in vu_pts)
        sxy = sum(p[0] * p[1] for p in vu_pts)
        den = n * sxx - sx * sx
        if den > 1e-9:
            a = (n * sxy - sx * sy) / den
            b = (sy - a * sx) / n
    return max(-120.0, a * x + b)


def learn(n, norm=None, db=None):
    now = time.time()
    if norm is not None:
        last_norm[n] = (norm, now)
        db, t = last_db.get(n, (None, 0))
        if db is None or now - t > 0.3:
            return
    else:
        last_db[n] = (db, now)
        norm, t = last_norm.get(n, (None, 0))
        if norm is None or now - t > 0.3:
            return
    if db > -119 and 0.0 < norm <= 1.0:
        p = (round(norm, 4), round(db, 2))
        if p not in cal_pts:
            cal_pts.append(p)
            dirty["t"] = dirty["t"] or now


def cal_step(now):
    c = cal
    if now < c["t"]:
        return
    pts = [-70, -60, -50, -40, -30, -24, -18, -12, -9, -6, -3, 0, 3, 6, 9, 12]
    if c["i"] < len(pts):
        to_reaper("vol", float(pts[c["i"]]), c["n"])
        c["i"] += 1
        c["t"] = now + 0.3
    else:
        to_reaper("vol", float(c["orig"]), c["n"])
        c["on"] = False
        log(f"Kalibrierung fertig: {len(cal_pts)} Punkte, Spur {c['n']} zurueckgesetzt")
        dirty["t"] = dirty["t"] or now



def match_addr(addr):
    """OSC-Adresse von REAPER -> (art, n) oder None"""
    p = addr.strip("/").split("/")
    if p[0] == "master":
        if p[1:] == ["volume", "db"]:
            return "mfader", 0
        if p[1:] == ["mute"]:
            return "mmute", 0
        if p[1:] == ["vu", "L"]:
            return "mvuL", 0
        if p[1:] == ["vu", "R"]:
            return "mvuR", 0
        return None
    if p[0] == "track" and len(p) >= 3 and p[1].isdigit():
        n = int(p[1]) - args.track_offset
        if not 1 <= n <= max_track():
            return None
        rest = "/".join(p[2:])
        return {"volume/db": "fader", "volume": "volnorm", "vu": "vu", "name": "name", "color": "color", "mute": "mute",
                 "solo": "solo", "select": "sel"}.get(rest), n
    return None


def from_reaper(addr, v):
    """Eine OSC-Nachricht von REAPER verarbeiten und ggf. an den DC16 weiterreichen.
    Ablauf: Namen/Farben/VU/Fader-Normwerte haben Sonderwege; sonst rstate (REAPER-Zustand) und
    state (Pultanzeige) aktualisieren und nur bei echter Aenderung schreiben. quiet_until unterdrueckt
    das Echo einer Pultbedienung (REAPER meldet sie zurueck, der Fader soll nicht gegenhalten)."""
    m = match_addr(addr)
    if not m or m[0] is None:
        return
    art, n = m
    now = time.time()
    osc_stat["n"][art] = osc_stat["n"].get(art, 0) + 1
    osc_stat["maxT"] = max(osc_stat["maxT"], n)
    osc_stat["last"] = now
    if art == "vu" and n == 1:
        osc_stat["vu1"] = (v, now)
    if art == "name":
        t = clean_name(str(v))
        if names.get(n, "") != t:
            names[n] = t
            dirty["t"] = dirty["t"] or now
            if S["verbose"]:
                log(f"REAPER Name Spur {n}: {t!r}")
            if cur_page() is not None and strip_of(n)[0] == cur_page():
                send_name(strip_of(n)[1])
        return
    if art == "color":
        ci = color_index(v)
        if S["verbose"]:
            log(f"REAPER Farbe Spur {n}: {v!r} -> Index {ci}")
        if rstate["color"].get(n) != ci:
            rstate["color"][n] = ci
            dirty["t"] = dirty["t"] or now
            to_dc16("color", n, ci)
        return
    if art == "volnorm":
        learn(n, norm=v)
        return
    if art == "vu":
        if vm["on"] and vm["n"] == n:
            vm["max"] = max(vm["max"], v)
        if cur_page() is not None and strip_of(n)[0] == cur_page():
            i = meter_ids_of_channel(strip_of(n)[1])
            live[i] = vu_to_db(v)
            live_t[i] = now
        return
    if art in ("mvuL", "mvuR"):
        i = 310 if art == "mvuL" else 311
        live[i] = vu_to_db(v)
        live_t[i] = now
        return
    if art == "fader":
        learn(n, db=v)
        if cal["on"] and n == cal["n"]:
            return                                # waehrend der Kalibrierung nicht an den DC16
    if art == "sel":
        if not v:
            return
        rstate["sel"] = n
    elif art in ("mfader", "mmute"):
        rstate[art] = v
    else:
        v = max(-120.0, v) if art == "fader" else int(v)
        rstate[art][n] = v
    dirty["t"] = dirty["t"] or time.time()
    if S["verbose"]:
        log(f"REAPER {addr} = {v}")
    if time.time() < quiet_until.get((art, n), 0):
        return                                    # Echo einer DC16-Bedienung
    cur = {"fader": state["fader"], "mute": state["mute"], "solo": state["solo"]}.get(art)
    if art in ("fader", "mute", "solo"):
        old = cur.get(n)
        if old is not None and abs(old - v) < 0.05:
            return
        cur[n] = v
    elif art in ("mfader", "mmute"):
        if state[art] is not None and abs(state[art] - v) < 0.05:
            return
        state[art] = v
    elif art == "sel":
        if state["sel"] == n:
            return
        state["sel"] = n
        v = n
    to_dc16(art, n, v)


# ---------------------------------------------------------------- Writes des DC16
def items_of(pl):
    """cmd-0x13-Nutzdaten -> (Feldtyp, [(Index, Wert), ...]).
    Format-Hi-Nibble: 0 Block ab Index, 1 Meter (hier ignoriert), sonst Paare [Index][Wert]."""
    w = struct.unpack(">%dI" % (len(pl) // 4), pl)
    if len(w) < 3:
        return 0, []
    idx, fm = w[0], w[1]
    low, hi = fm & 0xFFFF, fm >> 28
    if hi == 1:
        return low, []
    if hi == 0:
        return low, [(idx + k, v) for k, v in enumerate(w[2:])]
    return low, [(idx, w[2])] + [(w[j], w[j + 1]) for j in range(3, len(w) - 1, 2)]


def fl(w): return struct.unpack(">f", struct.pack(">I", w))[0]
def it(w): return struct.unpack(">i", struct.pack(">I", w))[0]


def on_write(pl):
    """Schreibzugriff des DC16 (Fader, Mute, Solo, Select, Layerwechsel) auswerten und an REAPER schicken.
    Nur Strips der aktuellen Seite zaehlen. Unbekannte Schreibzugriffe erscheinen im Log mit 'v' als
    'WRITE (unbekannt)' - so findet man neue Indizes (z.B. Master-Mute, Encoder, Sub/VCA-Layer)."""
    low, items = items_of(pl)
    for idx, w in items:
        ev = None
        p = cur_page()
        if low == 0x200 and idx == 0x9e:
            if S["verbose"] or not args.no_pages:
                log(f"DC16: Layer {it(w)}")
            set_page(it(w))
            continue
        if p is None:
            continue
        if low == 0x500:
            if BASE <= idx < BASE + REC * NCH:
                n, o = divmod(idx - BASE, REC)
                n += 1
                if o == FADER_OFF[p]:
                    ev = ("fader", p * NCH + n, fl(w))
                elif o == 7:
                    ev = ("mute", p * NCH + n, it(w))
            elif idx == IDX_MASTER_FADER and p == 0:
                ev = ("mfader", 0, fl(w))
            elif idx == IDX_MASTER_MUTE and p == 0:
                ev = ("mmute", 0, it(w))
        elif low == 0x200:
            if 24 <= idx <= 55:
                ev = ("solo", p * NCH + idx - 23, it(w))
            elif idx == 0x96 and 1 <= it(w) <= NCH:
                ev = ("sel", p * NCH + it(w), p * NCH + it(w))
        if ev is None:
            if S["verbose"]:
                log(f"WRITE (unbekannt) fmt=0x{low:04x} idx={idx} w=0x{w:08x}")
            continue
        art, n, v = ev
        prev_sel = state["sel"] if art == "sel" else None
        quiet_until[(art, n)] = time.time() + 0.4
        if art in ("fader", "mute", "solo"):
            rstate[art][n] = v
        elif art in ("mfader", "mmute"):
            rstate[art] = v
        else:
            rstate["sel"] = n
        dirty["t"] = dirty["t"] or time.time()
        if art in ("fader", "mute", "solo"):
            state[art][n] = v
        elif art in ("mfader", "mmute"):
            state[art] = v
        else:
            state["sel"] = n
        if S["verbose"] or art != "fader":
            log(f"DC16: {art} {n} = {v:.2f}" if isinstance(v, float) else f"DC16: {art} {n} = {v}")
        if art == "sel":
            # Auswahl exklusiv: erst alle Spuren abwaehlen, sonst addiert REAPER und verlinkt die Fader
            if not args.no_osc:
                osc_out.sendto(osc_msg(ADDR["unsel"], 1.0), (args.reaper_host, args.reaper_port))
            if prev_sel and prev_sel != n:
                to_reaper("sel", 0, prev_sel)
        to_reaper({"fader": "vol", "mfader": "mvol"}.get(art, art), v, n)


live = {}                              # Meter-ID -> Pegel (dB), von der Konsole oder spaeter von REAPER


def meter_default(i):
    """Ruhewert einer Meter-ID: aus dem Profil, sonst Schema. Pro Kanal 7 IDs ab 34+7(n-1): +0 Pegel,
    +2 = 60.0, +5 = 0.0 (Bedeutung unklar, evtl. Dynamik/GR); Master 310/311; 314 Ruhewert 0.0."""
    if i in meter_idle:
        return meter_idle[i]
    if 34 <= i < 34 + 7 * NCH:
        return {0: -120.0, 2: 60.0, 5: 0.0}.get((i - 34) % 7, -120.0)
    return 0.0 if i == 314 else -120.0


def meter_ids_of_channel(n):
    return 34 + 7 * (n - 1)            # Pegel-ID des Kanals n; Master LR: 310 (L), 311 (R)


def meter_push():
    """Meter-Paket (cmd 0x13 flag 8, fmt 0x10000100) fuer die aktive Gruppe senden (25/s).
    Gruppen/IDs kommen vom DC16 (cmd 0x16); Pegel aus live{} (REAPER-VU), sonst Ruhewert.
    Nach VU_HOLD Sekunden ohne neuen Wert faellt der Pegel auf -120 dB."""
    g = S["grp"]
    ids = S["groups"].get(g) or []
    vals = []
    now = time.time()
    for i in ids:
        v = live.get(i)
        if v is not None and now - live_t.get(i, now) > VU_HOLD:
            v = live[i] = -120.0                  # keine Daten mehr von REAPER -> leise
        if v is None:
            v = meter_default(i)
            if (34 <= i < 34 + 7 * NCH and (i - 34) % 7 == 0) or i in (310, 311):
                v = -120.0
        vals.append(v)
    send_req(8, 0x13, struct.pack(">II", g, 0x10000100) + struct.pack(">%df" % len(vals), *vals))


def handle(ident, flag, cmd, pl):
    """Ein Frame vom DC16 verarbeiten. Reihenfolge des Handshakes ist wichtig:
    DC16 cmd 0x06 -> wir antworten und senden boot_a (Anfragen 03, 02, 0e ...), jeweils die naechste
    erst nach der Antwort des DC16; nach seiner cmd-0x06-Anfrage mit Nutzdaten 00000006 senden wir
    den Zustandsdump (boot_b). Antworten auf DC16-Anfragen stammen aus dem Profil (replies/fallback).
    flag 8 = Benachrichtigung: cmd 0x16 Meter-Gruppen, cmd 0x13 Schreibzugriff (-> on_write)."""
    if flag & 1:
        if cmd != 0x01 and S["qa"] and S["qa"][0][0] != 0x06:
            c, p = S["qa"].pop(0)
            send_req(0, c, p)
        return
    if flag == 0:
        rep = replies.get((cmd, pl))
        if rep is None:
            rep = fallback.get(cmd)
        if rep is None:
            log(f"?? unbekannte Anfrage cmd=0x{cmd:02x} {pl[:32].hex(' ')}")
            rep = b""
        send(frame(ident, 1, cmd, rep))
        if cmd == 0x06 and not S["sentA"]:
            S["sentA"] = True
            S["qa"] = list(boot_a)
            c, p = S["qa"].pop(0)
            send_req(0, c, p)
            log("DC16 verbunden, Handshake laeuft")
        elif cmd == 0x0e and S["qa"]:
            c, p = S["qa"].pop(0)
            send_req(0, c, p)
        elif cmd == 0x06 and pl == b"\x00\x00\x00\x06" and not S["sentB"]:
            S["sentB"] = True
            for c, p in boot_b:
                if c == 0x18 and p[4:8] == bytes.fromhex("00590500"):
                    p = name_table_payload()
                elif c == 0x13 and p[4:8] == bytes.fromhex("00000200") and not args.no_pages:
                    o = 8 + (0x9e - struct.unpack(">I", p[0:4])[0]) * 4      # Start immer auf Layer LR
                    if 8 <= o <= len(p) - 4:
                        p = p[:o] + b"\0\0\0\0" + p[o + 4:]
                send_req(0, c, p)
            S["ready_at"] = time.time() + 2.0
            log("Zustandsdump gesendet")
        elif cmd == 0x15 and len(pl) >= 12:
            g, _, x = struct.unpack(">III", pl[:12])
            iv = (x >> 16) & 0xFFFF
            if iv:
                S["grp"], S["iv"], S["nxt_m"] = g, iv / 1000.0, 0.0
        return
    if flag == 8:
        if cmd == 0x16:
            w = struct.unpack(">%dI" % (len(pl) // 4), pl)
            if w[0] == 0xFFFFFFFF:
                S["groups"].clear()
                S["grp"] = None
                ack = b"\x00\x00\x00\x00"
            else:
                S["groups"][w[0]] = list(w[1:])
                ack = struct.pack(">I", 1)
            send(frame(ident, 9, 0x16, ack))
        elif cmd == 0x13:
            on_write(pl)
        elif S["verbose"]:
            log(f"?? flag=8 cmd=0x{cmd:02x} {pl[:32].hex(' ')}")


def feed(data):
    """TCP-Bytes puffern und in Frames zerlegen; bei falscher Kopfpruefsumme Byte fuer Byte neu syncen."""
    S["buf"] += data
    while len(S["buf"]) >= 8:
        b = S["buf"]
        if b[0] != 0xAB or struct.unpack(">H", b[6:8])[0] != (~sum(b[:6]) & 0xFFFF):
            S["buf"] = b[1:]
            continue
        n = struct.unpack(">H", b[2:4])[0] * 4
        tot = 8 + (n + 4 if n else 0)
        if len(b) < tot:
            return
        S["buf"] = b[tot:]
        handle(b[1], b[4], b[5], bytes(b[8:8 + n]))


# ---------------------------------------------------------------- Konsole (Thread, auch Windows)
cmdq = queue.Queue()


def stdin_thread():
    for line in sys.stdin:
        cmdq.put(line)


def command(line):
    """Konsolenbefehl ausfuehren (Syntax siehe Modulkopf). Kanalnummern = Strips der aktuellen Seite."""
    p = line.split()
    if not p:
        return
    try:
        if p[0] == "f":
            to_dc16("fader", T_of(int(p[1])), float(p[2]))
        elif p[0] == "m":
            to_dc16("mute", T_of(int(p[1])), int(p[2]))
        elif p[0] == "s":
            to_dc16("solo", T_of(int(p[1])), int(p[2]))
        elif p[0] == "stat":
            log(f"Seite {cur_page()}, DC16 verbunden={bool(S['conn'])}, Dump={S['sentB']}, "
                f"Meter-Gruppe={S['grp']}, Gruppen={ {hex(g): len(i) for g, i in S['groups'].items()} }")
            log(f"REAPER-Nachrichten: {osc_stat['n']}, hoechste Spur {osc_stat['maxT']}, "
                f"letzte vor {time.time() - osc_stat['last']:.1f}s" if osc_stat["last"] else "REAPER: noch nichts empfangen")
            log(f"VU Spur 1: {osc_stat['vu1']}")
        elif p[0] == "refresh":
            refresh_page()
            sync_all()
        elif p[0] == "page":                   # page <layer>: Seite von Hand wechseln (Test)
            set_page(int(p[1]))
        elif p[0] == "raw":
            v = p[3]
            push(int(p[1], 16), int(p[2]),
                 struct.pack(">f", float(v)) if "." in v else struct.pack(">i", int(v)))
        elif p[0] == "colortest":              # colortest <kanal>: alle Farbindizes 0..17 durchschalten
            ct.update(on=True, n=T_of(int(p[1]) if len(p) > 1 else 1), i=0, t=0.0)
            log("Farbtest: alle 2 s ein neuer Index, Display beobachten")
        elif p[0] == "color":                  # color <kanal> <index>
            T = T_of(int(p[1]))
            rstate["color"][T] = int(p[2])
            to_dc16("color", T, int(p[2]))
            dirty["t"] = dirty["t"] or time.time()
        elif p[0] == "name":                   # name <eintrag> <text>   (Kanal n = Eintrag n, Aux n = 51+n)
            names[T_of(int(p[1]))] = clean_name(" ".join(p[2:]))
            send_name(int(p[1]))
            dirty["t"] = dirty["t"] or time.time()
        elif p[0] == "probe":                  # probe <fmt-hex> <von> <bis>: Index als 4-stelliger Text
            fm, a, b = int(p[1], 16), int(p[2]), int(p[3])
            for idx in range(a, min(b, 9999) + 1):
                send_req(S["flag"], 0x13, struct.pack(">II", idx, fm) + f"{idx:04d}".encode())
            log(f"probe: {b - a + 1} Woerter geschrieben (Text = absoluter Index)")
        elif p[0] == "vm":                     # vm <spur> <dB>: 3 s messen, Punkt (VU-Wert, dB) lernen
            vm.update(on=True, n=int(p[1]), db=float(p[2]), max=0.0, t_end=time.time() + 3.0)
            log(f"Messe 3 s Spur {p[1]} (Signal = {p[2]} dB am Meter, also nach dem Fader) ...")
        elif p[0] == "vclear":
            vu_pts.clear()
            log("VU-Messpunkte geloescht")
        elif p[0] == "cal":                    # cal [spur]: Fader-Skala von REAPER lernen
            n = int(p[1]) if len(p) > 1 else NCH
            cal.update(on=True, n=n, i=0, t=0.0, orig=rstate["fader"].get(n, 0.0))
            log(f"Kalibrierung auf Spur {n} (wird danach zurueckgesetzt)")
        elif p[0] == "mt":                     # mt <kanal|0=Master> <dB>
            v = float(p[2])
            if int(p[1]) == 0:
                live[310] = live[311] = v
            else:
                live[meter_ids_of_channel(int(p[1]))] = v
        elif p[0] == "flag":
            S["flag"] = int(p[1])
        elif p[0] == "v":
            S["verbose"] = not S["verbose"]
            log("verbose", S["verbose"])
        elif p[0] == "q":
            sys.exit(0)
    except (ValueError, IndexError):
        log("Eingabefehler")


if sys.stdin and sys.stdin.isatty():
    threading.Thread(target=stdin_thread, daemon=True).start()

# ---------------------------------------------------------------- Hauptschleife
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp.bind(("", 61000))
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("", 50001))
srv.listen(1)
log(f"bereit auf {args.ip}: UDP 61000, TCP 50001; REAPER {args.reaper_host}:{args.reaper_port}, "
    f"Feedback auf UDP {args.listen_port}")
seen = set()
# Diagnose: gehoert --ip wirklich einem Adapter dieses Rechners? (Der DC16 verbindet sich mit dieser
# Adresse aus dem Discovery-Paket; stimmt sie nicht, kommt nie eine TCP-Verbindung zustande.)
try:
    _t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _t.bind((args.ip, 0))
    _t.close()
except OSError:
    log(f"WARNUNG: {args.ip} gehoert zu keinem Netzwerkadapter dieses Rechners! "
        f"--ip muss die Adapter-IP im DC16-Netz sein (Windows: 'ipconfig').")
log("Wenn nach 'Discovery beantwortet' keine 'TCP-Verbindung ... angenommen' folgt: "
    "Firewall (eingehend TCP 50001) oder falsche --ip.")

# Eine einzige Schleife (select, 20 ms): Discovery beantworten (UDP 61000), DC16 annehmen (TCP 50001),
# OSC von REAPER lesen, Konsole, Farbdatei, periodische Aufgaben (Speichern, Herzschlag, Meter).
while True:
    socks = [udp, srv] + ([S["conn"]] if S["conn"] else []) + ([] if args.no_osc else [osc_in])
    try:
        r, _, _ = select.select(socks, [], [], 0.02)
    except (OSError, ValueError):
        r = []
    for s in r:
        if s is udp:
            data, addr = udp.recvfrom(2048)
            if len(data) == len(disc) and data[:4] == disc[:4] and data[8:12] != disc[8:12]:
                udp.sendto(disc, addr)
                if addr[0] not in seen:
                    seen.add(addr[0])
                    log(f"Discovery von {addr[0]} beantwortet")
        elif s is srv:
            c, addr = srv.accept()
            log(f"TCP-Verbindung vom DC16 ({addr[0]}) angenommen")
            if S["conn"]:
                drop("(neue Verbindung)")
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            reset()
            S["conn"] = c
            S["nxt_hb"] = time.time() + 4.0
        elif s is osc_in:
            data, _ = osc_in.recvfrom(65536)
            for a, v in osc_parse(data):
                from_reaper(a, v)
        elif s is S["conn"]:
            try:
                data = s.recv(65536)
            except OSError:
                data = b""
            if not data:
                drop()
            else:
                feed(data)
    while not cmdq.empty():
        command(cmdq.get())
    now = time.time()
    poll_colors(now)
    if refresh_due["t"] and now >= refresh_due["t"]:
        refresh_due["t"] = 0.0
        sync_all()
    if cal["on"]:
        cal_step(now)
    if ct["on"] and now >= ct["t"]:
        if ct["i"] <= 17:
            to_dc16("color", ct["n"], ct["i"])
            log(f"Farbindex {ct['i']}")
            ct["i"] += 1
            ct["t"] = now + 2.0
        else:
            ct["on"] = False
            to_dc16("color", ct["n"], rstate["color"].get(ct["n"], 0))
            log("Farbtest fertig")
    if vm["on"] and now >= vm["t_end"]:
        vm["on"] = False
        if vm["max"] > 0:
            vu_pts.append((round(vm["max"], 4), vm["db"]))
            dirty["t"] = dirty["t"] or now
            log(f"VU-Punkt: norm {vm['max']:.4f} = {vm['db']} dB  ({len(vu_pts)} Punkte)")
        else:
            log("keine VU-Werte von REAPER empfangen (Wiedergabe laeuft?)")
    if dirty["t"] and now - dirty["t"] > 2.0:
        dirty["t"] = 0.0
        save_state()
    if S["conn"]:
        if S["sentB"] and not S["synced"] and now >= S["ready_at"]:
            S["synced"] = True
            sync_all()
        if now >= S["nxt_hb"]:
            send_req(0, 0x01)
            S["nxt_hb"] = now + 4.0
        if S["conn"] and S["grp"] is not None and now >= S["nxt_m"]:
            meter_push()
            S["nxt_m"] = max(S["nxt_m"] + S["iv"], now) if S["nxt_m"] else now + S["iv"]
