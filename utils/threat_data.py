# utils/threat_data.py
# ══════════════════════════════════════════════════════════════════
#  Initial Phishing Domain Seed List
#  Source: Known Discord/Steam/Gaming phishing campaigns
#  Loaded into: malicious_links table (Supabase) on bot startup
#  Runtime additions: !link-add command + VirusTotal auto-learn
# ══════════════════════════════════════════════════════════════════

PHISHING_DOMAINS: set[str] = {
    # ── Discord Impersonation ──────────────────────────────────
    "discord-nitro.gift",       # fake nitro gift page
    "free-nitro.ru",
    "discordapp.gift",
    "discord.gift.ru",
    "nitro-discord.com",
    "dlscord.com",              # typosquat (d-l instead of i)
    "discrod.com",              # typosquat (missing 'c')
    "discordnitro.online",
    "discordapp.io",            # fake discordapp domain
    "discord.rip",
    "discord-giveaway.com",
    "discordnitro.gift",
    "qr-discord.com",           # QR code login hijack
    "discord-boost.net",
    "discord-gift.org",
    "free-discord.ru",
    "discordapp.co",            # typosquat (.co not .com)
    "nitro.gift.ru",
    "discordskins.com",

    # ── Steam / Gaming ────────────────────────────────────────
    "free-steam.ru",
    "steamgift.ru",
    "steamgifts.ru",
    "steamtrade.ru",
    "epicgames.gift",           # fake Epic Games giveaway
    "csgo-skins.ru",
    "tradeit.ru",
    "skinport.gift",            # fake skinport trading site
}

# ── Regex Patterns ─────────────────────────────────────────────
import re

# Zalgo text: Unicode combining characters used to distort chat rendering
# Matches 3+ consecutive combining marks (diacritics, overlays, etc.)
ZALGO_RE = re.compile(
    r'[\u0300-\u036f'     # Combining Diacritical Marks
    r'\u0489'             # Combining Cyrillic Millions Sign
    r'\u1dc0-\u1dff'      # Combining Diacritical Marks Supplement
    r'\u20d0-\u20ff'      # Combining Diacritical Marks for Symbols
    r'\ufe20-\ufe2f'      # Combining Half Marks
    r']{3,}',
    re.UNICODE
)

# URL extractor: captures the hostname from http/https links
# Used as first step before domain lookup in PHISHING_DOMAINS
URL_RE = re.compile(
    r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})',
    re.IGNORECASE
)
