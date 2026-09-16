from pathlib import Path

from PIL import Image, ImageOps
from rich.style import Style
from rich.text import Text
from textual.widgets import Static


class AtlasPortrait(Static):
    """Render the bundled artwork using two grayscale pixels per terminal cell."""

    def on_resize(self, event):
        width = min(event.size.width, 70)
        height = min(event.size.height, 35)
        if width < 1 or height < 1:
            return
        with Image.open(Path(__file__).parent / "assets" / "atlas-logo.jpeg") as source:
            portrait = source.crop((0, 0, source.width, int(source.height * .77)))
            pixels = ImageOps.invert(ImageOps.grayscale(portrait))
            pixels = ImageOps.contain(pixels, (width, height * 2))
            canvas = Image.new("L", (width, height * 2), 0)
            canvas.paste(pixels, ((width - pixels.width) // 2, 0))
        output = Text(no_wrap=True)
        for y in range(height):
            for x in range(width):
                top = canvas.getpixel((x, 2 * y))
                bottom = canvas.getpixel((x, 2 * y + 1))
                output.append("▀", Style(color=f"rgb({top},{top},{top})", bgcolor=f"rgb({bottom},{bottom},{bottom})"))
            if y + 1 < height:
                output.append("\n")
        self.update(output)
