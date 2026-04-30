# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — CAPTCHA Image Generator
#  Generates a local image-based CAPTCHA challenge using Pillow.
#  Returns a random 5-6 character string + a discord.File image.
#
#  Blueprint reference: Module 1 — Gatekeeping & Verification
#  "On new member join → bot sends a DM with a CAPTCHA challenge."
#
#  No external API needed — all generation is done locally.
# ══════════════════════════════════════════════════════════════════

import io
import math
import random
import string
import logging

import discord
from PIL import Image, ImageDraw, ImageFont, ImageFilter

logger = logging.getLogger("antiraid.captcha")

# ── CAPTCHA Configuration ──────────────────────────────────────
CAPTCHA_LENGTH = 6         # Characters in the challenge
IMAGE_WIDTH = 280
IMAGE_HEIGHT = 90

# Character set — exclude ambiguous characters (0/O, 1/I/l)
CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# Colors — dark text on light backgrounds for readability
_BG_COLORS = [
    (240, 240, 250),  # light blue-grey
    (250, 245, 235),  # warm cream
    (235, 250, 240),  # mint
    (250, 240, 245),  # blush
    (245, 245, 255),  # lavender
]

_TEXT_COLORS = [
    (40, 40, 80),     # dark navy
    (80, 30, 30),     # dark crimson
    (30, 60, 30),     # dark green
    (60, 30, 80),     # dark purple
    (30, 50, 80),     # dark steel
]


def _generate_code(length: int = CAPTCHA_LENGTH) -> str:
    """Generate a random alphanumeric CAPTCHA string."""
    return "".join(random.choices(CHARSET, k=length))


def _create_captcha_image(code: str) -> io.BytesIO:
    """
    Render a CAPTCHA image with the given code.
    Applies visual noise (lines, dots, distortion) to prevent OCR.

    Returns:
        BytesIO buffer containing the PNG image data.
    """
    bg_color = random.choice(_BG_COLORS)
    img = Image.new("RGB", (IMAGE_WIDTH, IMAGE_HEIGHT), bg_color)
    draw = ImageDraw.Draw(img)

    # ── Try to use a built-in monospace font ───────────────────
    font_size = 42
    try:
        # Try common system fonts
        for font_name in ["arial.ttf", "Arial.ttf", "DejaVuSans-Bold.ttf", "LiberationMono-Bold.ttf"]:
            try:
                font = ImageFont.truetype(font_name, font_size)
                break
            except OSError:
                continue
        else:
            # Fallback to default bitmap font
            font = ImageFont.load_default()
    except Exception:
        font = ImageFont.load_default()

    # ── Draw noise lines (anti-OCR) ────────────────────────────
    for _ in range(random.randint(4, 7)):
        x1 = random.randint(0, IMAGE_WIDTH)
        y1 = random.randint(0, IMAGE_HEIGHT)
        x2 = random.randint(0, IMAGE_WIDTH)
        y2 = random.randint(0, IMAGE_HEIGHT)
        line_color = (
            random.randint(100, 180),
            random.randint(100, 180),
            random.randint(100, 180),
        )
        draw.line([(x1, y1), (x2, y2)], fill=line_color, width=random.randint(1, 2))

    # ── Draw noise dots ────────────────────────────────────────
    for _ in range(random.randint(80, 150)):
        x = random.randint(0, IMAGE_WIDTH - 1)
        y = random.randint(0, IMAGE_HEIGHT - 1)
        dot_color = (
            random.randint(80, 200),
            random.randint(80, 200),
            random.randint(80, 200),
        )
        draw.point((x, y), fill=dot_color)

    # ── Draw each character with random offset & rotation ──────
    char_spacing = IMAGE_WIDTH // (len(code) + 1)
    text_color = random.choice(_TEXT_COLORS)

    for i, char in enumerate(code):
        x = char_spacing * (i + 1) - 10 + random.randint(-5, 5)
        y = (IMAGE_HEIGHT // 2) - 20 + random.randint(-8, 8)

        # Create a small image for each character to rotate it
        char_img = Image.new("RGBA", (50, 60), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_draw.text((5, 5), char, font=font, fill=text_color)

        # Random rotation (-25 to +25 degrees)
        angle = random.randint(-25, 25)
        char_img = char_img.rotate(angle, expand=True, resample=Image.BICUBIC)

        # Paste onto main image
        img.paste(char_img, (x - 10, y - 10), char_img)

    # ── Apply slight blur for anti-OCR ─────────────────────────
    img = img.filter(ImageFilter.SMOOTH)

    # ── Draw more noise arcs over the text ─────────────────────
    draw = ImageDraw.Draw(img)
    for _ in range(random.randint(2, 4)):
        x1 = random.randint(-20, IMAGE_WIDTH // 2)
        y1 = random.randint(-20, IMAGE_HEIGHT)
        x2 = random.randint(IMAGE_WIDTH // 2, IMAGE_WIDTH + 20)
        y2 = random.randint(-20, IMAGE_HEIGHT)
        arc_color = (
            random.randint(60, 160),
            random.randint(60, 160),
            random.randint(60, 160),
        )
        draw.arc(
            [(x1, y1), (x2, y2)],
            start=random.randint(0, 90),
            end=random.randint(180, 360),
            fill=arc_color,
            width=2,
        )

    # ── Export to BytesIO ──────────────────────────────────────
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer


def generate_captcha() -> tuple[str, discord.File]:
    """
    Generate a CAPTCHA challenge.

    Returns:
        Tuple of (code_string, discord.File) where:
          - code_string is the correct answer (e.g., "H4KP7N")
          - discord.File is the PNG image ready to send via Discord
    """
    code = _generate_code()
    image_buffer = _create_captcha_image(code)

    file = discord.File(
        fp=image_buffer,
        filename="captcha_challenge.png",
        description="CAPTCHA verification challenge",
    )

    logger.debug(f"Generated CAPTCHA: {code}")
    return code, file
