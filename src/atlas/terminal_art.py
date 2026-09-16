from PIL import Image, ImageOps
from rich.text import Text
from textual.widgets import Static


class AtlasWordmark(Static):
    def on_resize(self, event):
        if event.size.width < 36:
            self.update("[b]A T L A S[/b]\n\nSECURITY AGENT\n\nANALISE\nPREVINA\nEVOLUA")
        else:
            self.update("[b]  ▄▄    ▄▄▄▄▄  ▄      ▄▄    ▄▄▄▄\n ▄██▄     █    █     ▄██▄   █\n █▄▄█     █    █     █▄▄█   ▀▀▀█\n █  █     █    █▄▄▄  █  █   ▄▄▄█[/b]\n\nS E C U R I T Y  A G E N T\n\nANALISE · PREVINA · EVOLUA")


class AtlasPortrait(Static):
    """Reuse the monochrome Braille artwork from the original black menu."""

    def on_resize(self, event):
        from atlas.tui import ATLAS_PORTRAIT

        lines = ATLAS_PORTRAIT.splitlines()
        width = min(event.size.width, max(map(len, lines)))
        height = min(event.size.height, len(lines))
        if width < 1 or height < 1:
            return
        if width == max(map(len, lines)) and height == len(lines):
            self.update(Text(ATLAS_PORTRAIT, style="#f0f0f0", no_wrap=True))
            return
        dots = ((0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2), (0, 3), (1, 3))
        source = Image.new("1", (max(map(len, lines)) * 2, len(lines) * 4))
        for y, line in enumerate(lines):
            for x, char in enumerate(line):
                value = ord(char) - 0x2800
                if 0 <= value <= 255:
                    for bit, (dx, dy) in enumerate(dots):
                        if value & (1 << bit):
                            source.putpixel((x * 2 + dx, y * 4 + dy), 1)
        pixels = ImageOps.contain(source, (width * 2, height * 4), Image.Resampling.NEAREST)
        canvas = Image.new("1", (width * 2, height * 4))
        canvas.paste(pixels, ((canvas.width - pixels.width) // 2, (canvas.height - pixels.height) // 2))
        output = Text(style="#f0f0f0", no_wrap=True)
        for y in range(height):
            for x in range(width):
                value = sum(1 << bit for bit, (dx, dy) in enumerate(dots)
                            if canvas.getpixel((x * 2 + dx, y * 4 + dy)))
                output.append(chr(0x2800 + value))
            if y + 1 < height:
                output.append("\n")
        self.update(output)
