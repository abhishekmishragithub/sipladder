"""Convert browser-check screenshots into the README animation. Requires Pillow."""
from PIL import Image, ImageOps
from pathlib import Path
frames = []
for name in ['01-drop.png', '02-ladder.png', '03-detail.png']:
    image = Image.open(Path('docs/screenshots') / name).convert('RGB')
    image = ImageOps.pad(image, (1100, 890), color='#101516', method=Image.Resampling.LANCZOS)
    frames.append(image.quantize(colors=128))
frames[0].save('docs/demo.gif', save_all=True, append_images=frames[1:], duration=[1800, 2400, 2400], loop=0, optimize=True)
