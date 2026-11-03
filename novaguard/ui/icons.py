"""Small original line icons, rendered at 3x for crisp Windows scaling."""
from PIL import Image, ImageDraw
import customtkinter as ctk

from novaguard.ui.theme import COLORS


def _draw(name: str, color: str, size: int) -> Image.Image:
    scale = 4
    image = Image.new("RGBA", (24 * scale, 24 * scale))
    d = ImageDraw.Draw(image)
    def line(points, width=1.6):
        d.line([(int(x * scale), int(y * scale)) for x, y in points], fill=color, width=round(width * scale), joint="curve")
    def box(bounds, radius=2):
        d.rounded_rectangle(tuple(int(n * scale) for n in bounds), radius=radius * scale, outline=color, width=round(1.6 * scale))
    def ellipse(bounds):
        d.ellipse(tuple(int(n * scale) for n in bounds), outline=color, width=round(1.6 * scale))
    if name == "shield":
        line([(12, 2.5), (20, 6), (19, 14), (16, 18), (12, 21.5), (8, 18), (5, 14), (4, 6), (12, 2.5)])
        line([(8, 11.5), (11, 14.5), (16, 9)])
    elif name == "grid":
        for x, y in [(3, 3), (14, 3), (3, 14), (14, 14)]:
            box((x, y, x + 7, y + 7), 1)
    elif name == "scan":
        ellipse((4, 3, 17, 16))
        line([(15, 15), (21, 21)])
        line([(7, 10), (10, 10), (12, 7)])
    elif name == "lock":
        box((5, 10, 19, 21))
        d.arc((7 * scale, 2 * scale, 17 * scale, 16 * scale), 180, 360, fill=color, width=round(1.6 * scale))
        line([(12, 14), (12, 17)])
    elif name == "clock":
        ellipse((3, 3, 21, 21))
        line([(12, 6), (12, 12), (16, 14)])
    elif name == "settings":
        ellipse((5, 5, 19, 19))
        ellipse((9, 9, 15, 15))
        for points in [[(12, 1), (12, 5)], [(12, 19), (12, 23)], [(1, 12), (5, 12)], [(19, 12), (23, 12)],
                       [(4, 4), (7, 7)], [(17, 17), (20, 20)], [(4, 20), (7, 17)], [(17, 7), (20, 4)]]:
            line(points)
    elif name == "pulse":
        line([(2, 12), (7, 12), (10, 5), (14, 19), (17, 12), (22, 12)])
    elif name == "file":
        line([(14, 3), (5, 3), (5, 21), (19, 21), (19, 8), (14, 3), (14, 8), (19, 8)])
        line([(9, 12), (15, 12)])
        line([(9, 16), (14, 16)])
    elif name == "folder":
        line([(3, 7), (3, 4), (10, 4), (13, 7), (21, 7), (21, 20), (3, 20), (3, 7), (21, 7)])
    elif name == "check":
        line([(5, 12), (10, 17), (20, 6)], 2)
    elif name == "arrow":
        line([(5, 12), (19, 12), (14, 7)])
        line([(19, 12), (14, 17)])
    elif name == "book":
        box((4, 3, 20, 21))
        line([(8, 3), (8, 21)])
        line([(12, 8), (16, 8)])
        line([(12, 12), (16, 12)])
    elif name == "briefcase":
        box((3, 7, 21, 21))
        box((8, 3, 16, 7), 1)
        line([(3, 12), (21, 12)])
        line([(12, 10), (12, 15)])
    elif name == "moon":
        d.arc((4 * scale, 3 * scale, 21 * scale, 21 * scale), 65, 290, fill=color, width=round(1.6 * scale))
        d.arc((10 * scale, 1 * scale, 25 * scale, 18 * scale), 85, 260, fill=color, width=round(1.6 * scale))
    elif name == "chevron":
        line([(8, 9), (12, 13), (16, 9)])
    else:
        ellipse((4, 4, 20, 20))
        line([(12, 8), (12, 13)])
        line([(12, 16), (12, 17)])
    return image.resize((size * 3, size * 3), Image.Resampling.LANCZOS)


def icon(name: str, tone: str = "text_soft", size: int = 20) -> ctk.CTkImage:
    colors = COLORS[tone] if tone != "white" else ("#ffffff", "#ffffff")
    return ctk.CTkImage(_draw(name, colors[0], size), _draw(name, colors[1], size), size=(size, size))
