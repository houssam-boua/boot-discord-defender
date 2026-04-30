# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Malicious Link Scanner (Layer 1)
#  In-memory domain cache backed by the malicious_links DB table.
#  Directly from blueprint Section 8.3.
#
#  Layer 1: Instant O(1) lookup against in-memory cache.
#  Layer 2: VirusTotal deep scan (Phase 2 — not implemented yet).
# ══════════════════════════════════════════════════════════════════

import re
import logging

from utils.threat_data import PHISHING_DOMAINS, URL_RE

logger = logging.getLogger("antiraid.linkscanner")

# In-memory cache — loaded from DB on startup, updated on !link-add
_domain_cache: set[str] = set(PHISHING_DOMAINS)


async def load_cache_from_db(pool) -> None:
    """
    Call once at bot startup to sync cache with DB.
    Merges the seed list (PHISHING_DOMAINS) with any domains
    that were added at runtime via !link-add or VirusTotal auto-learn.
    """
    rows = await pool.fetch("SELECT domain FROM malicious_links")
    _domain_cache.update(row["domain"] for row in rows)
    logger.info(
        f"✅ Link scanner cache loaded — {len(_domain_cache)} domains tracked"
    )


def is_known_malicious(url: str) -> bool:
    """
    Instant O(1) lookup against in-memory cache.

    Extracts the hostname from the URL via regex, strips 'www.',
    and checks against the cached domain set.

    Args:
        url: The full URL string to check.

    Returns:
        True if the domain is in the malicious cache.
    """
    match = URL_RE.search(url)
    if not match:
        return False
    domain = match.group(1).lower().lstrip("www.")
    return domain in _domain_cache


def scan_message_urls(content: str) -> list[str]:
    """
    Extract all URLs from a message and return any that match
    the malicious domain cache (Layer 1 only).

    Args:
        content: The raw message text.

    Returns:
        List of flagged malicious URLs found in the message.
    """
    urls = re.findall(r'https?://[^\s<>"]+', content)
    flagged = []
    for url in urls:
        if is_known_malicious(url):
            flagged.append(url)
    return flagged


def add_to_cache(domain: str) -> None:
    """
    Add a domain to the in-memory cache at runtime.
    Called by !link-add command after DB insert.
    """
    _domain_cache.add(domain.lower().lstrip("www."))


def remove_from_cache(domain: str) -> None:
    """
    Remove a domain from the in-memory cache at runtime.
    Called by !link-remove command after DB delete.
    """
    _domain_cache.discard(domain.lower().lstrip("www."))


def get_cached_domains() -> set[str]:
    """Return a copy of the current domain cache."""
    return set(_domain_cache)


def get_cache_size() -> int:
    """Return the current number of domains in cache."""
    return len(_domain_cache)

