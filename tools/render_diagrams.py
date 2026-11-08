"""Render the English vault architecture figures as SVG and PNG files.

Run from any directory with Python 3 and Pillow installed. Also refreshes
the diagrams embedded in index.html so that the article stays self-contained.
"""

from html import escape
from pathlib import Path
import math
import re

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1] / "assets"
FONT_ROOT = Path("/usr/share/fonts/truetype/dejavu")
INK = "#14243b"
MUTED = "#54657b"
LINE = "#60738c"


class Figure:
    def __init__(self, height, title):
        self.w, self.h = 1600, height
        self.image = Image.new("RGB", (self.w, self.h), "#f5f7fc")
        self.draw = ImageDraw.Draw(self.image)
        self.svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="{height}" viewBox="0 0 1600 {height}" role="img" aria-label="{escape(title, quote=True)}">',
            f"<title>{escape(title)}</title>",
            '<rect width="100%" height="100%" fill="#f5f7fc"/>',
        ]

    def rect(self, box, fill="white", outline="#cbd5e3", radius=20):
        self.draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=2)
        x0, y0, x1, y1 = box
        self.svg.append(
            f'<rect x="{x0}" y="{y0}" width="{x1-x0}" height="{y1-y0}" rx="{radius}" fill="{fill}" stroke="{outline}" stroke-width="2"/>'
        )

    def text(self, x, y, value, size=28, color=INK, bold=False, mono=False, center=False):
        filename = "DejaVuSansMono.ttf" if mono else "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
        font = ImageFont.truetype(str(FONT_ROOT / filename), size)
        for i, line in enumerate(value.split("\n")):
            top = y + i * int(size * 1.42)
            length = self.draw.textlength(line, font=font)
            left = x - length / 2 if center else x
            if left < 15 or left + length > self.w - 15 or top + size > self.h - 10:
                raise ValueError(f"Text outside figure bounds: {line}")
            self.draw.text((left, top), line, font=font, fill=color, anchor="lt")
            family = "DejaVu Sans Mono" if mono else "DejaVu Sans"
            weight = "bold" if bold else "normal"
            self.svg.append(
                f'<text x="{left}" y="{top}" fill="{color}" font-family="{family}" font-size="{size}" font-weight="{weight}" dominant-baseline="text-before-edge">{escape(line)}</text>'
            )

    def arrow(self, points, color=LINE):
        self.draw.line(points, fill=color, width=4, joint="curve")
        x0, y0 = points[-2]
        x1, y1 = points[-1]
        angle = math.atan2(y1-y0, x1-x0)
        tip = [(x1, y1), (x1-16*math.cos(angle-.45), y1-16*math.sin(angle-.45)),
               (x1-16*math.cos(angle+.45), y1-16*math.sin(angle+.45))]
        self.draw.polygon(tip, fill=color)
        path = " ".join(f"{x},{y}" for x, y in points)
        polygon = " ".join(f"{x},{y}" for x, y in tip)
        self.svg.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="4" stroke-linejoin="round"/>')
        self.svg.append(f'<polygon points="{polygon}" fill="{color}"/>')

    def title(self, number, title, subtitle):
        self.text(50, 35, f"{number}  {title}", 38, bold=True)
        self.text(50, 96, subtitle, 24, color=MUTED)

    def save(self, name):
        ROOT.mkdir(parents=True, exist_ok=True)
        (ROOT / f"{name}.svg").write_text("\n".join(self.svg + ["</svg>"]) + "\n", encoding="utf-8")
        self.image.save(ROOT / f"{name}.png")


def secret_to_addresses():
    f = Figure(900, "From one secret to native vault addresses")
    f.title("1", "From one secret to native vault addresses", "Each network N and vault index i has a separate authority branch.")
    f.rect((40, 165, 725, 745), "#e9f6f3", "#91cbbd")
    f.rect((755, 165, 1560, 745), "#edf1fd", "#b3c2ec")
    f.text(65, 185, "PRIVATE: WALLET ONLY", 25, color="#17654f", bold=True)
    f.text(780, 185, "PUBLIC: COMMITMENTS AND ADDRESSES", 25, color="#38528c", bold=True)
    f.rect((65, 380, 315, 535), outline="#7eb3a5")
    f.text(190, 407, "Parano1d secret S", 23, bold=True, center=True)
    f.text(190, 463, "One secret backup", 22, color=MUTED, center=True)
    for cy, label in [(325, "EVM"), (590, "SOL")]:
        f.rect((405, cy-70, 695, cy+70), outline="#7eb3a5")
        f.text(550, cy-46, f"s_{label},i", 30, bold=True, center=True)
        f.text(550, cy+8, "KDF(S, N, i, v)", 22, mono=True, center=True)
        f.rect((790, cy-70, 1090, cy+70), outline="#9cabd1")
        f.text(940, cy-46, f"C_{label},i", 30, bold=True, center=True)
        f.text(940, cy+8, "C = Commit(s)", 23, mono=True, center=True)
        f.arrow([(695, cy), (790, cy)])
    f.arrow([(315, 457), (360, 457), (360, 325), (405, 325)])
    f.arrow([(360, 457), (360, 590), (405, 590)])
    f.rect((1170, 255, 1525, 395), "#fff5df", "#d8bb73")
    f.text(1347, 275, "Parano1d contract", 27, bold=True, center=True)
    f.text(1347, 324, "0x...", 31, mono=True, center=True)
    f.text(1347, 370, "Factory + init code + salt", 19, center=True)
    f.rect((1170, 520, 1525, 660), "#f4eefe", "#b9a1d5")
    f.text(1347, 540, "Parano1d PDA", 29, bold=True, center=True)
    f.text(1347, 590, "PDA: base58...", 25, mono=True, center=True)
    f.text(1347, 635, "Program ID + C + seeds", 20, center=True)
    f.arrow([(1090, 325), (1170, 325)])
    f.arrow([(1090, 590), (1170, 590)])
    f.text(65, 700, "Secrets stay inside the wallet.", 23, color="#17654f")
    f.text(780, 700, "C is a public authority commitment.", 23, color="#38528c")
    f.text(50, 783, "The authority commitment and the native account address are distinct.", 27, bold=True)
    f.text(50, 830, "Address recovery also uses the public deployment manifest, network, version and index.", 24, color=MUTED)
    f.save("01-secret-to-addresses")
    social = Image.new("RGB", (1200, 630), "#f5f7fc")
    social.paste(f.image.resize((1120, 630), Image.Resampling.LANCZOS), (40, 0))
    social.save(ROOT / "native-asset-vaults-social.png", optimize=True)


def code_and_assets():
    f = Figure(1030, "Where code and native assets live")
    f.title("2", "Where code and native assets live", "Deploy and authenticate the account before funding it.")
    f.rect((40, 165, 775, 925), "#fff8e9", "#dfc686")
    f.rect((825, 165, 1560, 925), "#f4eefe", "#c4b2e0")
    f.text(75, 185, "EVM NETWORK (L1 OR L2)", 29, color="#805d0b", bold=True)
    f.text(860, 185, "SOLANA", 29, color="#68408b", bold=True)
    f.rect((90, 260, 725, 375), outline="#d8bb73")
    f.text(407, 282, "Parano1d vault factory", 30, bold=True, center=True)
    f.text(407, 334, "Deploys fixed code with CREATE2", 23, color=MUTED, center=True)
    f.arrow([(407, 375), (407, 465)])
    f.text(430, 405, "creates a personal contract", 23, color="#805d0b")
    f.rect((90, 465, 725, 780), outline="#d8bb73")
    f.text(407, 487, "Parano1d contract: 0x...", 29, bold=True, center=True)
    f.text(120, 550, "Code: verifier + withdrawal logic", 25)
    f.text(120, 599, "State: C_EVM, nonce, parameters", 25)
    f.text(120, 648, "Account balance: native coin", 25)
    f.text(120, 708, "Replay state survives an empty balance.", 22, color=MUTED)
    f.rect((875, 260, 1510, 375), outline="#bba0d9")
    f.text(1192, 282, "Parano1d vault program", 30, bold=True, center=True)
    f.text(1192, 334, "Fixed verifier and withdrawal logic", 23, color=MUTED, center=True)
    f.arrow([(1192, 375), (1192, 465)])
    f.text(1210, 405, "controls its vault accounts", 23, color="#68408b")
    f.rect((875, 465, 1510, 780), outline="#bba0d9")
    f.text(1192, 487, "Parano1d PDA: base58...", 29, bold=True, center=True)
    f.text(905, 550, "Account owner: vault program", 25)
    f.text(905, 599, "State: C_SOL, nonce, parameters", 25)
    f.text(905, 648, "Account balance: native SOL", 25)
    f.text(905, 708, "Keep state alive with its rent reserve.", 22, color=MUTED)
    f.text(90, 826, "Receive native coins at the contract.", 24, color="#805d0b")
    f.text(875, 826, "Receive SOL at the initialized PDA.", 24, color="#68408b")
    f.text(90, 873, "Code and replay state remain installed.", 23, color="#805d0b")
    f.text(875, 873, "Persistent state prevents nonce reset.", 23, color="#68408b")
    f.text(50, 964, "Assets stay on their native chains. The Parano1d wallet creates withdrawal proofs.", 26, bold=True)
    f.save("02-where-code-and-assets-live")


def withdrawal():
    f = Figure(1090, "A withdrawal authorized by a proof")
    f.title("3", "A withdrawal authorized by a proof", "Authorization is checked on the chain that holds the funds.")
    f.rect((50, 155, 1550, 270), "#edf1fd", "#b3c2ec")
    f.text(80, 177, "Request R: protocol, network, vault, verifier parameters, nonce, recipient,", 25)
    f.text(80, 222, "native asset, amount, expiry and exact fee terms.", 25)
    f.rect((60, 335, 475, 610), "#e9f6f3", "#91cbbd")
    f.text(267, 360, "Parano1d wallet", 30, bold=True, center=True)
    f.text(90, 421, "1. Constructs request R", 24)
    f.text(90, 468, "2. Derives vault secret", 24)
    f.text(90, 515, "3. Produces proof", 24)
    f.text(90, 562, "Secret stays here", 23, color="#17654f", bold=True)
    f.rect((590, 375, 925, 575), outline="#b6c3d5")
    f.text(757, 400, "Relayer", 30, bold=True, center=True)
    f.text(757, 455, "Submits R + proof", 25, center=True)
    f.text(757, 507, "Pays network fees", 23, color=MUTED, center=True)
    f.arrow([(475, 475), (590, 475)])
    f.arrow([(925, 475), (1030, 475)])
    f.rect((1030, 330, 1540, 735), outline="#9cabd1")
    f.text(1285, 355, "Parano1d contract / program", 24, bold=True, center=True)
    f.text(1060, 417, "1. Reads C from vault state", 24)
    f.text(1060, 466, "2. Checks R and proof", 24)
    f.text(1060, 515, "3. Checks nonce and expiry", 24)
    f.text(1060, 564, "4. Consumes the nonce", 24)
    f.text(1060, 613, "5. Transfers native assets", 24)
    f.text(1060, 672, "One atomic final operation", 23, color="#38528c", bold=True)
    f.arrow([(1285, 735), (1285, 820)])
    f.rect((1030, 820, 1540, 925), "#e9f6f3", "#91cbbd")
    f.text(1285, 845, "Recipient receives native assets", 24, bold=True, center=True)
    f.text(60, 690, "Only the public request", 24, color=MUTED)
    f.text(60, 731, "and proof leave the wallet.", 24, color=MUTED)
    f.text(590, 650, "The relay signature", 22, color=MUTED)
    f.text(590, 689, "delivers a transaction.", 22, color=MUTED)
    f.text(590, 728, "The proof authorizes", 22, color=MUTED)
    f.text(590, 767, "the vault withdrawal.", 22, color=MUTED)
    f.rect((50, 986, 1550, 1050), "#edf1fd", "#b3c2ec")
    f.text(800, 1005, "A different recipient, amount or context requires a new authorization.", 25, bold=True, center=True)
    f.save("03-withdrawal-with-proof")


if __name__ == "__main__":
    secret_to_addresses()
    code_and_assets()
    withdrawal()
    article = ROOT.parent / "index.html"
    if article.exists():
        html = article.read_text(encoding="utf-8")
        for name in ("01-secret-to-addresses", "02-where-code-and-assets-live", "03-withdrawal-with-proof"):
            svg = ROOT / f"{name}.svg"
            name = svg.stem
            pattern = rf"(<!-- diagram:{re.escape(name)}:start -->).*?(<!-- diagram:{re.escape(name)}:end -->)"
            replacement = lambda match: match[1] + "\n" + svg.read_text(encoding="utf-8") + "        " + match[2]
            html, count = re.subn(pattern, replacement, html, flags=re.S)
            if count != 1:
                raise ValueError(f"Expected one article embedding for {name}, found {count}")
        article.write_text(html, encoding="utf-8")
    print("Created three English SVG diagrams and PNG exports.")
