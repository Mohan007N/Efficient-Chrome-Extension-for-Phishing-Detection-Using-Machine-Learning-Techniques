"""
create_icons.py — Run this ONCE to generate the extension icons from the source PNG.

Usage (from the project root):
    python create_icons.py
"""

import os
from PIL import Image

src = os.path.join(os.path.dirname(__file__), "chrome_extension", "icons", "shield_source.png")
out_dir = os.path.join(os.path.dirname(__file__), "chrome_extension", "icons")
os.makedirs(out_dir, exist_ok=True)

if not os.path.exists(src):
    # Fall back to generating a simple programmatic icon using Pillow
    from PIL import ImageDraw, ImageFont
    for size in [16, 32, 48, 128]:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Draw dark circle background
        margin = max(1, size // 10)
        draw.ellipse([margin, margin, size - margin, size - margin], fill="#0f1117")
        # Draw shield outline
        draw.ellipse([margin + 2, margin + 2, size - margin - 2, size - margin - 2],
                     outline="#3b82f6", width=max(1, size // 16))
        # Save
        out_path = os.path.join(out_dir, f"icon{size}.png")
        img.save(out_path)
        print(f"✅ Generated {out_path}")
else:
    img = Image.open(src)
    for size in [16, 32, 48, 128]:
        resized = img.resize((size, size), Image.LANCZOS)
        out_path = os.path.join(out_dir, f"icon{size}.png")
        resized.save(out_path)
        print(f"✅ Saved {out_path}")

print("\n✅ All icons created. You can now load the extension in Chrome.")
