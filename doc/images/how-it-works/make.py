#!/usr/bin/env python3
"""
Схемы для doc/how-it-works*.md - одна геометрия, подписи на двух языках.

    python3 doc/images/how-it-works/make.py

Пишет рядом <схема>.ru.svg и <схема>.en.svg. Фон у схем белый, а не
прозрачный: GitHub в тёмной теме иначе показал бы тёмный текст на тёмном.
Текст в SVG не переносится сам, поэтому строки разбиты здесь руками;
поменяв подпись, проверьте, что она влезла (откройте .svg в браузере).
"""
import os
from xml.sax.saxutils import escape

OUT = os.path.dirname(os.path.abspath(__file__))
SANS = "'DejaVu Sans','Segoe UI','Helvetica Neue',Arial,sans-serif"
MONO = "'DejaVu Sans Mono',Consolas,'Courier New',monospace"

INK = "#1e293b"      # основной текст
MUTED = "#475569"    # пояснения
BLUE = ("#eff6ff", "#2563eb", "#1e3a8a")      # ваши устройства: фон, рамка, текст
GRAY = ("#f1f5f9", "#64748b", "#334155")      # ретранслятор и сеть
GREEN = ("#ecfdf5", "#059669", "#065f46")     # защита, ключи
AMBER = ("#fffbeb", "#d97706", "#92400e")     # то, что видно
RED = "#dc2626"


class Svg:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.parts = [f'<rect x="0" y="0" width="{w}" height="{h}" fill="#ffffff"/>']

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, size=14, weight="normal", fill=INK, anchor="middle",
             family=SANS, italic=False):
        style = ' font-style="italic"' if italic else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
                 f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{style}>'
                 f'{escape(s)}</text>')

    def lines(self, x, y, items, size=13, step=None, **kw):
        step = step or round(size * 1.35)
        for i, s in enumerate(items):
            self.text(x, y + i * step, s, size=size, **kw)
        return y + len(items) * step

    def box(self, x, y, w, h, colors, rx=14, width=2):
        fill, stroke, _ = colors
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{width}"/>')

    def pill(self, cx, cy, s, colors, size=12, pad=12):
        fill, stroke, ink = colors
        w = len(s) * size * 0.62 + 2 * pad
        self.add(f'<rect x="{cx - w / 2:.1f}" y="{cy - size}" width="{w:.1f}" '
                 f'height="{size * 2}" rx="{size}" fill="{fill}" stroke="{stroke}"/>')
        self.text(cx, cy + size * 0.36, s, size=size, weight="bold", fill=ink)

    def arrow(self, x1, y1, x2, y2, color=MUTED, both=False, width=2.5):
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
                 f'stroke-width="{width}" marker-end="url(#ah)"'
                 + (' marker-start="url(#ah)"' if both else "") + "/>")

    def lock(self, cx, cy, s=1.0, color=GREEN[1]):
        w, h = 22 * s, 17 * s
        self.add(f'<path d="M {cx - 7 * s} {cy - h / 2} v {-6 * s} a {7 * s} {7 * s} 0 0 1 '
                 f'{14 * s} 0 v {6 * s}" fill="none" stroke="{color}" stroke-width="{2.6 * s}"/>')
        self.add(f'<rect x="{cx - w / 2}" y="{cy - h / 2}" width="{w}" height="{h}" '
                 f'rx="{3 * s}" fill="{color}"/>')
        self.add(f'<circle cx="{cx}" cy="{cy + 1 * s}" r="{2.4 * s}" fill="#ffffff"/>')

    def key(self, cx, cy, s=1.0, color=GREEN[1]):
        self.add(f'<circle cx="{cx - 9 * s}" cy="{cy}" r="{6 * s}" fill="none" '
                 f'stroke="{color}" stroke-width="{2.6 * s}"/>')
        self.add(f'<path d="M {cx - 3 * s} {cy} h {16 * s} v {5 * s} M {cx + 8 * s} {cy} '
                 f'v {4 * s}" fill="none" stroke="{color}" stroke-width="{2.6 * s}"/>')

    def monitor(self, cx, cy, color):
        self.add(f'<rect x="{cx - 26}" y="{cy - 20}" width="52" height="34" rx="4" '
                 f'fill="#ffffff" stroke="{color}" stroke-width="2.5"/>')
        self.add(f'<path d="M {cx - 10} {cy + 22} h 20 M {cx} {cy + 14} v 8" '
                 f'stroke="{color}" stroke-width="2.5"/>')

    def phone(self, cx, cy, color):
        self.add(f'<rect x="{cx - 12}" y="{cy - 22}" width="24" height="44" rx="5" '
                 f'fill="#ffffff" stroke="{color}" stroke-width="2.5"/>')
        self.add(f'<circle cx="{cx}" cy="{cy + 16}" r="2" fill="{color}"/>')

    def server(self, cx, cy, color):
        for i in range(3):
            y = cy - 21 + i * 15
            self.add(f'<rect x="{cx - 24}" y="{y}" width="48" height="12" rx="3" '
                     f'fill="#ffffff" stroke="{color}" stroke-width="2.2"/>')
            self.add(f'<circle cx="{cx + 15}" cy="{y + 6}" r="2" fill="{color}"/>')

    def bubble(self, cx, cy, s, colors):
        fill, stroke, ink = colors
        w = len(s) * 8.2 + 22
        self.add(f'<path d="M {cx - w / 2} {cy - 14} h {w} v 26 h {-w + 22} l -8 9 v -9 '
                 f'h -14 z" fill="#ffffff" stroke="{stroke}" stroke-width="2" '
                 f'stroke-linejoin="round"/>')
        self.text(cx, cy + 4, s, size=13, weight="bold", fill=ink)

    def person(self, cx, cy, letter, colors, faded=False):
        fill, stroke, ink = colors
        op = ' opacity="0.35"' if faded else ""
        self.add(f'<g{op}><circle cx="{cx}" cy="{cy}" r="17" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="2.2"/>')
        self.text(cx, cy + 5, letter, size=15, weight="bold", fill=ink)
        self.add("</g>")

    def mark(self, x, y, kind):
        """✓ хранится / ✗ нет / • видно - простыми фигурами, без шрифтовых значков."""
        if kind == "yes":
            self.add(f'<path d="M {x - 5} {y - 4} l 4 4 l 7 -8" fill="none" '
                     f'stroke="{GREEN[1]}" stroke-width="2.6" stroke-linecap="round" '
                     f'stroke-linejoin="round"/>')
        elif kind == "no":
            self.add(f'<path d="M {x - 5} {y - 9} l 9 9 M {x + 4} {y - 9} l -9 9" '
                     f'stroke="{RED}" stroke-width="2.4" stroke-linecap="round"/>')
        else:
            self.add(f'<circle cx="{x}" cy="{y - 4}" r="3.6" fill="{AMBER[1]}"/>')

    def save(self, name):
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                f'viewBox="0 0 {self.w} {self.h}">'
                '<defs><marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" '
                'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>')
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            f.write(head + "\n".join(self.parts) + "</svg>\n")


T = {
    "ru": {
        "you": "Ваше устройство",
        "you_lines": ["шифрует перед отправкой,", "расшифровывает", "при получении"],
        "keys_here": "ключи – только здесь",
        "relay": "Ретранслятор",
        "relay_sub": "(сервер-посредник)",
        "relay_lines": ["пересылает шифр", "участникам комнаты"],
        "no_keys": "ключей нет",
        "peers": "Собеседники",
        "peers_lines": ["расшифровывают", "своими экземплярами", "ключа"],
        "cipher": "шифр",
        "arch_caption": "Сквозное шифрование: открыть данные могут только устройства участников",

        "steps": [
            (["Вы пишете", "сообщение"], "bubble"),
            (["Шифрование", "на вашем", "устройстве"], "lock"),
            (["По интернету", "идёт только", "шифр"], "cipher"),
            (["Ретранслятор", "пересылает,", "не открывая"], "server"),
            (["Собеседник", "расшифровывает"], "bubble"),
        ],
        "hello": "Привет!",
        "aes": "AES-256-GCM",
        "tls": "+ TLS по желанию",
        "msg_caption": "Так же передаются файлы, голос и видео",

        "col_dev": "Ваши устройства",
        "dev_stores": "Хранится:",
        "dev_items": [("yes", ["Ключ личности –", "закрытая часть", "зашифрована"]),
                      ("yes", ["История переписки"]),
                      ("yes", ["Доверенные ключи", "собеседников"]),
                      ("yes", ["Полученные файлы"])],
        "dev_note": ["Защищены устройством:", "блокировка экрана,", "шифрование диска"],
        "col_relay": "Ретранслятор",
        "stores": "Хранит:",
        "relay_items": [("yes", ["Псевдоним и открытый", "ключ – если вы их", "зарегистрировали"]),
                        ("yes", ["Список контактов –", "зашифрован"]),
                        ("yes", ["Письма тем, кто не в сети –", "запечатаны, до 30 дней"])],
        "not_stores": "Не хранит:",
        "relay_no": [("no", ["Переписку, звонки, файлы"]),
                     ("no", ["Ключи шифрования"]),
                     ("no", ["Названия комнат и имена"])],
        "col_net": "Сеть",
        "visible": "Видно:",
        "net_items": [("dot", ["Что соединение есть"]),
                      ("dot", ["IP-адреса"]),
                      ("dot", ["Время и объём данных"])],
        "invisible": "Не видно:",
        "net_no": [("no", ["Содержимое – только шифр"])],
        "net_note": ["С TLS скрыта и форма", "трафика"],

        "people": ["А", "Б", "В"],
        "stage_titles": ["Анна и Борис", "Вошла Вера", "Борис вышел"],
        "key_n": "ключ №{}",
        "stage_notes": [["Переписываются", "под ключом №1"],
                        ["Новый ключ. Старое", "Вера не прочтёт"],
                        ["Новый ключ. Новое", "Борис не прочтёт"]],
        "plus": "+ Вера",
        "minus": "– Борис",
        "rot_caption": "Новый ключ рассылается каждому участнику отдельно, запечатанный его ключом личности",

        "fp_left": "Телефон Анны",
        "fp_left_lbl": "Ключ Бориса:",
        "fp_right": "Компьютер Бориса",
        "fp_right_lbl": "Мой ключ:",
        "match": "совпадает",
        "fp_caption": "Сравните отпечатки при встрече или по телефону: совпали – посредника между вами нет",
    },
    "en": {
        "you": "Your device",
        "you_lines": ["encrypts before sending,", "decrypts", "on arrival"],
        "keys_here": "keys stay here",
        "relay": "Relay",
        "relay_sub": "(intermediary server)",
        "relay_lines": ["forwards ciphertext", "to the room"],
        "no_keys": "no keys",
        "peers": "Your contacts",
        "peers_lines": ["decrypt", "with their own", "copies of the key"],
        "cipher": "ciphertext",
        "arch_caption": "End-to-end encryption: only the participants' devices can open the data",

        "steps": [
            (["You write", "a message"], "bubble"),
            (["Encrypted", "on your", "device"], "lock"),
            (["Only ciphertext", "crosses the", "internet"], "cipher"),
            (["The relay", "forwards it", "unopened"], "server"),
            (["Your contact", "decrypts it"], "bubble"),
        ],
        "hello": "Hello!",
        "aes": "AES-256-GCM",
        "tls": "+ optional TLS",
        "msg_caption": "Files, voice and video travel the same way",

        "col_dev": "Your devices",
        "dev_stores": "Kept here:",
        "dev_items": [("yes", ["Identity key – its secret", "part encrypted"]),
                      ("yes", ["Message history"]),
                      ("yes", ["Trusted keys of", "your contacts"]),
                      ("yes", ["Received files"])],
        "dev_note": ["Protected by the device:", "screen lock,", "disk encryption"],
        "col_relay": "Relay",
        "stores": "Keeps:",
        "relay_items": [("yes", ["Handle and public key –", "if you registered them"]),
                        ("yes", ["Contact list –", "encrypted"]),
                        ("yes", ["Mail for those offline –", "sealed, up to 30 days"])],
        "not_stores": "Does not keep:",
        "relay_no": [("no", ["Messages, calls, files"]),
                     ("no", ["Encryption keys"]),
                     ("no", ["Room or display names"])],
        "col_net": "Network",
        "visible": "Visible:",
        "net_items": [("dot", ["That a connection exists"]),
                      ("dot", ["IP addresses"]),
                      ("dot", ["Timing and volume"])],
        "invisible": "Not visible:",
        "net_no": [("no", ["Content – only ciphertext"])],
        "net_note": ["With TLS, the shape of", "the traffic is hidden too"],

        "people": ["A", "B", "C"],
        "stage_titles": ["Alice and Bob", "Carol joins", "Bob leaves"],
        "key_n": "key #{}",
        "stage_notes": [["Talk under", "key #1"],
                        ["New key. Carol cannot", "read what came before"],
                        ["New key. Bob cannot", "read what comes after"]],
        "plus": "+ Carol",
        "minus": "– Bob",
        "rot_caption": "The new key goes to each member separately, sealed with that member's identity key",

        "fp_left": "Alice's phone",
        "fp_left_lbl": "Bob's key:",
        "fp_right": "Bob's computer",
        "fp_right_lbl": "My key:",
        "match": "match",
        "fp_caption": "Compare fingerprints in person or over the phone: if they match, nobody sits in between",
    },
}


def architecture(t, lang):
    s = Svg(800, 300)
    boxes = [(20, BLUE, "dev", t["you"], None, t["you_lines"], t["keys_here"]),
             (295, GRAY, "srv", t["relay"], t["relay_sub"], t["relay_lines"], t["no_keys"]),
             (570, BLUE, "dev2", t["peers"], None, t["peers_lines"], t["keys_here"])]
    for x, c, icon, title, sub, lines, badge in boxes:
        s.box(x, 30, 210, 220, c)
        cx = x + 105
        if icon == "srv":
            s.server(cx, 70, c[1])
        else:
            s.monitor(cx - 22, 70, c[1])
            s.phone(cx + 30, 72, c[1])
        s.text(cx, 120, title, size=17, weight="bold", fill=c[2])
        y = 140
        if sub:
            s.text(cx, y, sub, size=12, fill=MUTED)
            y += 20
        s.lines(cx, y + 2, lines, size=13, fill=INK)
        if icon == "srv":
            s.pill(cx, 228, badge, ("#fef2f2", RED, "#991b1b"))
        else:
            s.pill(cx, 228, badge, GREEN)
    for x1, x2 in ((232, 293), (507, 568)):
        s.arrow(x1 + 4, 140, x2 - 4, 140, both=True)
        s.lock((x1 + x2) / 2, 118, 0.8)
        s.text((x1 + x2) / 2, 168, t["cipher"], size=11, fill=MUTED)
    s.text(400, 284, t["arch_caption"], size=14, weight="bold", fill=GREEN[2])
    s.save(f"architecture.{lang}.svg")


def message(t, lang):
    s = Svg(800, 250)
    w, gap, x0, y0, h = 138, 25, 5, 40, 160
    colors = [BLUE, GREEN, GRAY, GRAY, BLUE]
    for i, ((lines, icon), c) in enumerate(zip(t["steps"], colors)):
        x = x0 + i * (w + gap)
        cx = x + w / 2
        s.box(x, y0, w, h, c)
        s.add(f'<circle cx="{cx}" cy="{y0}" r="14" fill="{c[1]}"/>')
        s.text(cx, y0 + 5, str(i + 1), size=14, weight="bold", fill="#ffffff")
        if icon == "bubble":
            s.bubble(cx, y0 + 42, t["hello"], c)
        elif icon == "lock":
            s.lock(cx, y0 + 44, 1.2)
        elif icon == "cipher":
            s.add(f'<rect x="{cx - 52}" y="{y0 + 30}" width="104" height="26" rx="6" '
                  f'fill="#1e293b"/>')
            s.text(cx, y0 + 48, "8f3a…c91e", size=13, family=MONO, fill="#a7f3d0")
        else:
            s.server(cx, y0 + 44, c[1])
        s.lines(cx, y0 + 90, lines, size=13, weight="bold", fill=c[2])
        if i == 1:
            s.text(cx, y0 + h - 10, t["aes"], size=10, fill=MUTED)
        if i == 2:
            s.text(cx, y0 + h - 10, t["tls"], size=10, fill=MUTED)
        if i < 4:
            s.arrow(x + w + 4, y0 + h / 2, x + w + gap - 5, y0 + h / 2)
    s.text(400, 235, t["msg_caption"], size=13, fill=MUTED, italic=True)
    s.save(f"message.{lang}.svg")


def storage(t, lang):
    s = Svg(800, 400)
    w, gap, x0, top = 244, 22, 12, 15
    cols = [(t["col_dev"], BLUE), (t["col_relay"], GRAY), (t["col_net"], AMBER)]
    for i, (title, c) in enumerate(cols):
        x = x0 + i * (w + gap)
        s.box(x, top, w, 370, ("#ffffff", c[1], None), rx=14)
        s.add(f'<path d="M {x} {top + 46} v -32 a 14 14 0 0 1 14 -14 h {w - 28} '
              f'a 14 14 0 0 1 14 14 v 32 z" fill="{c[1]}"/>')
        s.text(x + w / 2, top + 30, title, size=16, weight="bold", fill="#ffffff")

    def items(x, y, lst):
        for kind, lines in lst:
            s.mark(x + 18, y, kind)
            y = s.lines(x + 34, y, lines, size=13, anchor="start") + 6
        return y

    def heading(x, y, label, color):
        s.text(x + 14, y, label, size=13, weight="bold", fill=color, anchor="start")
        return y + 22

    x = x0
    y = heading(x, top + 76, t["dev_stores"], GREEN[2])
    y = items(x, y, t["dev_items"])
    s.lines(x + 14, top + 318, t["dev_note"], size=12, anchor="start", fill=MUTED, italic=True)

    x = x0 + (w + gap)
    y = heading(x, top + 76, t["stores"], GREEN[2])
    y = items(x, y, t["relay_items"])
    y = heading(x, y + 8, t["not_stores"], "#991b1b")
    items(x, y, t["relay_no"])

    x = x0 + 2 * (w + gap)
    y = heading(x, top + 76, t["visible"], AMBER[2])
    y = items(x, y, t["net_items"])
    y = heading(x, y + 8, t["invisible"], "#991b1b")
    items(x, y, t["net_no"])
    s.lines(x + 14, top + 330, t["net_note"], size=12, anchor="start", fill=MUTED, italic=True)
    s.save(f"storage.{lang}.svg")


def rotation(t, lang):
    s = Svg(800, 290)
    w, gap, x0, top, h = 210, 75, 10, 20, 220
    members = [[0, 1], [0, 1, 2], [0, 2]]
    for i in range(3):
        x = x0 + i * (w + gap)
        cx = x + w / 2
        s.box(x, top, w, h, BLUE if i == 0 else GRAY)
        s.text(cx, top + 30, t["stage_titles"][i], size=15, weight="bold", fill=INK)
        n = len(members[i]) + (1 if i == 2 else 0)
        shown = members[i] + ([1] if i == 2 else [])
        for j, who in enumerate(shown):
            px = cx + (j - (n - 1) / 2) * 46
            new = (i == 1 and who == 2)
            gone = (i == 2 and who == 1)
            s.person(px, top + 70, t["people"][who], GREEN if new else BLUE, faded=gone)
        label = t["key_n"].format(i + 1)
        total = 28 + 8 + len(label) * 9.8          # значок, зазор, текст
        start = cx - total / 2
        s.key(start + 15, top + 122, 1.0)
        s.text(start + 36, top + 128, label, size=16, weight="bold", fill=GREEN[2],
               anchor="start")
        s.lines(cx, top + 165, t["stage_notes"][i], size=13, fill=INK)
        if i < 2:
            ax = x + w + 6
            s.arrow(ax, top + h / 2, ax + gap - 12, top + h / 2)
            s.text(ax + (gap - 6) / 2, top + h / 2 - 12, t["plus"] if i == 0 else t["minus"],
                   size=12, weight="bold", fill=GREEN[2] if i == 0 else "#991b1b")
    s.text(400, 274, t["rot_caption"], size=13, fill=MUTED, italic=True)
    s.save(f"rotation.{lang}.svg")


def fingerprint(t, lang):
    s = Svg(800, 250)
    fp = ["40:f6:8f:4a", "d2:4e:57:5b"]
    for x, title, lbl, colors in ((60, t["fp_left"], t["fp_left_lbl"], BLUE),
                                  (500, t["fp_right"], t["fp_right_lbl"], BLUE)):
        s.box(x, 20, 240, 170, colors, rx=20)
        s.text(x + 120, 50, title, size=15, weight="bold", fill=colors[2])
        s.text(x + 120, 84, lbl, size=13, fill=MUTED)
        s.add(f'<rect x="{x + 30}" y="{98}" width="180" height="62" rx="8" fill="#ffffff" '
              f'stroke="{colors[1]}"/>')
        s.lines(x + 120, 123, fp, size=16, family=MONO, weight="bold", fill=INK, step=24)
    s.add(f'<circle cx="400" cy="100" r="30" fill="{GREEN[0]}" stroke="{GREEN[1]}" '
          f'stroke-width="2.5"/>')
    s.add(f'<path d="M 386 100 l 9 9 l 17 -19" fill="none" stroke="{GREEN[1]}" '
          f'stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
    s.text(400, 152, t["match"], size=14, weight="bold", fill=GREEN[2])
    s.arrow(330, 100, 362, 100, both=False)
    s.arrow(470, 100, 438, 100, both=False)
    s.text(400, 228, t["fp_caption"], size=13, fill=MUTED, italic=True)
    s.save(f"fingerprint.{lang}.svg")


if __name__ == "__main__":
    for lang, t in T.items():
        architecture(t, lang)
        message(t, lang)
        storage(t, lang)
        rotation(t, lang)
        fingerprint(t, lang)
    print("diagrams written to", OUT)
