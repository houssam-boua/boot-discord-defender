# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Malicious Link Scanner
#  In-memory domain cache backed by the malicious_links DB table.
#
#  Layer 1: Instant O(1) lookup against in-memory cache.
#  Layer 2: VirusTotal v3 API deep scan for unknown URLs.
#           Malicious results are auto-learned into the DB + cache
#           so we never burn an API call on the same domain twice.
# ══════════════════════════════════════════════════════════════════

import re
import base64
import logging

import aiohttp

from config import Config
from utils.threat_data import PHISHING_DOMAINS, URL_RE

logger = logging.getLogger("antiraid.linkscanner")

# In-memory cache — loaded from DB on startup, updated on !link-add
_domain_cache: set[str] = set(PHISHING_DOMAINS)

# Singleton aiohttp session to prevent resource leaks.
_session: aiohttp.ClientSession | None = None

# Database pool reference — set at startup by init_pool()
_pool = None

# Redis reference — set at startup by init_redis()
_redis = None


# ══════════════════════════════════════════════════════════════════
#  Session & Pool Management
# ══════════════════════════════════════════════════════════════════


def init_pool(pool) -> None:
    """Store a reference to the asyncpg pool for VT auto-learn inserts."""
    global _pool
    _pool = pool


def init_redis(redis_client) -> None:
    """Store a reference to the Redis client for VT rate limiting."""
    global _redis
    _redis = redis_client


def get_session() -> aiohttp.ClientSession:
    """
    Get or create the singleton aiohttp session.
    Reuses a single TCP connection pool for all outbound HTTP calls.
    """
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
        )
    return _session


async def close_session() -> None:
    """Close the singleton session cleanly on bot shutdown."""
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None
        logger.info("  ✅ aiohttp session closed.")


# ══════════════════════════════════════════════════════════════════
#  Layer 1: In-Memory Domain Cache
# ══════════════════════════════════════════════════════════════════


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


def _extract_domain(url: str) -> str | None:
    """Extract and normalize domain from a URL."""
    match = URL_RE.search(url)
    if not match:
        return None
    return match.group(1).lower().lstrip("www.")


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
    domain = _extract_domain(url)
    if not domain:
        return False
    return domain in _domain_cache


def scan_message_urls(content: str) -> list[str]:
    """
    Extract all URLs from a message and return any that match
    the malicious domain cache (Layer 1 only — synchronous).

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


def extract_urls(content: str) -> list[str]:
    """Extract all URLs from message content (for Layer 2 scanning)."""
    return re.findall(r'https?://[^\s<>"]+', content)


# ══════════════════════════════════════════════════════════════════
#  Layer 2: VirusTotal v3 API Deep Scan
#
#  Three-layer protection against API abuse:
#    1. vt_scan_cache DB check — returns instantly for ANY previously scanned domain
#    2. Redis token bucket — enforces 4 requests/minute rate limit
#    3. Result caching — ALL results (clean + malicious) persisted to DB
# ══════════════════════════════════════════════════════════════════

# Minimum number of VT engines that must flag a URL as malicious.
# Set to 3 to avoid false positives from single-engine flags.
VT_MALICIOUS_THRESHOLD = 3

# VT free tier: 4 lookups per minute, 500 per day
VT_RATE_LIMIT = 4
VT_DAILY_QUOTA = 490  # Leave 10 call margin for safety


async def check_virustotal(url: str) -> int:
    """
    Query the VirusTotal v3 API for a URL reputation scan.

    Execution flow:
      1. Extract domain from URL.
      2. Check vt_scan_cache DB — if domain was scanned before, return cached result.
      3. Check Redis rate limiter — if over 4 calls/minute, skip (fail open).
      3b. Check Redis daily quota — if over 490 calls/day, skip (fail open).
      4. Call VT API.
      5. Cache the result in vt_scan_cache (clean OR malicious).
      6. If malicious, also insert into malicious_links + in-memory cache.

    Args:
        url: The full URL string to scan.

    Returns:
        Number of engines that flagged the URL as malicious.
        Returns 0 if cached clean, rate-limited, API fails, or key not set.
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return 0

    # ── Step 1: Extract domain ─────────────────────────────────
    domain = _extract_domain(url)
    if not domain:
        return 0

    # ── Step 2: Check DB cache (vt_scan_cache) ─────────────────
    # This catches BOTH previously-clean and previously-malicious domains
    if _pool:
        try:
            cached = await _pool.fetchrow(
                "SELECT is_malicious, positives FROM vt_scan_cache WHERE domain = $1",
                domain,
            )
            if cached:
                if cached["is_malicious"]:
                    logger.debug(f"VT cache HIT (malicious): {domain}")
                    return cached["positives"]
                else:
                    logger.debug(f"VT cache HIT (clean): {domain}")
                    return 0
        except Exception as e:
            logger.debug(f"VT cache check failed: {e}")

    # ── Step 3: Redis rate limiter (4 per minute) ──────────────
    if _redis:
        try:
            import time
            current_minute = int(time.time() // 60)
            rate_key = f"vt:ratelimit:{current_minute}"
            count = await _redis.incr(rate_key)
            if count == 1:
                await _redis.expire(rate_key, 60)
            if count > VT_RATE_LIMIT:
                logger.debug(
                    f"VT rate limit reached ({count}/{VT_RATE_LIMIT}/min) — skipping {domain}"
                )
                return 0  # Fail open — don't block the message
        except Exception as e:
            logger.debug(f"VT rate limit check failed: {e}")

    # ── Step 3b: Daily quota check (490/day) ───────────────────
    if _redis:
        try:
            from datetime import datetime as _dt, timezone as _tz
            daily_key = f"vt:daily:{_dt.now(_tz.utc).strftime('%Y-%m-%d')}"
            daily_count = await _redis.incr(daily_key)
            if daily_count == 1:
                await _redis.expire(daily_key, 86400)
            if daily_count > VT_DAILY_QUOTA:
                logger.warning(
                    f"⚠️ VT daily quota reached ({daily_count}/{VT_DAILY_QUOTA}) — "
                    f"skipping {domain}"
                )
                return 0  # Fail open
        except Exception as e:
            logger.debug(f"VT daily quota check failed: {e}")

    # ── Step 4: Call VT API ────────────────────────────────────
    try:
        session = get_session()

        # VT v3 uses base64url-encoded URL (no padding) as the identifier
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

        headers = {"x-apikey": api_key}
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        async with session.get(vt_url, headers=headers) as resp:
            if resp.status == 404:
                # URL not in VT database — submit for scanning, cache as clean
                await _submit_url_to_vt(url, headers)
                await _cache_vt_result(domain, is_malicious=False, positives=0)
                return 0

            if resp.status == 429:
                logger.warning("VT API rate limited (429) — backing off")
                return 0

            if resp.status != 200:
                logger.debug(f"VT API returned {resp.status} for {url}")
                return 0

            data = await resp.json()

        # Extract analysis stats
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_flagged = malicious + suspicious

        # ── Step 5: Cache result (clean OR malicious) ──────────
        is_malicious = total_flagged >= VT_MALICIOUS_THRESHOLD
        await _cache_vt_result(domain, is_malicious=is_malicious, positives=total_flagged)

        if is_malicious:
            # Step 6: Also insert into malicious_links + memory cache
            await _auto_learn_domain(domain, total_flagged)

            logger.warning(
                f"🔗 VT Layer 2 FLAGGED: {url} — "
                f"{malicious} malicious, {suspicious} suspicious"
            )

        return total_flagged

    except aiohttp.ClientError as e:
        logger.debug(f"VT API connection error: {e}")
        return 0
    except Exception as e:
        logger.error(f"VT Layer 2 scan error: {e}")
        return 0


async def _submit_url_to_vt(url: str, headers: dict) -> None:
    """Submit an unknown URL to VirusTotal for analysis."""
    try:
        session = get_session()
        async with session.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
        ) as resp:
            if resp.status == 200:
                logger.debug(f"Submitted {url} to VT for analysis")
    except Exception:
        pass  # Non-critical — silently fail


async def _cache_vt_result(domain: str, *, is_malicious: bool, positives: int) -> None:
    """
    Cache a VT scan result (clean OR malicious) in vt_scan_cache.
    This is the key to preventing repeated API calls on clean domains.
    """
    if not _pool:
        return
    try:
        await _pool.execute(
            """
            INSERT INTO vt_scan_cache (domain, is_malicious, positives)
            VALUES ($1, $2, $3)
            ON CONFLICT (domain) DO UPDATE
                SET is_malicious = $2,
                    positives = $3,
                    scanned_at = NOW()
            """,
            domain,
            is_malicious,
            positives,
        )
    except Exception as e:
        logger.debug(f"Failed to cache VT result for {domain}: {e}")


async def _auto_learn_domain(domain: str, threat_score: int) -> None:
    """
    Persist a VirusTotal-flagged domain into the DB and in-memory cache.
    This is the critical caching step that prevents repeat API calls.
    """
    # Add to in-memory cache immediately
    _domain_cache.add(domain)

    # Persist to PostgreSQL
    if _pool:
        try:
            await _pool.execute(
                """
                INSERT INTO malicious_links (domain, threat_level, source)
                VALUES ($1, $2, 'virustotal')
                ON CONFLICT (domain) DO UPDATE
                    SET threat_level = GREATEST(malicious_links.threat_level, $2),
                        updated_at = NOW()
                """,
                domain,
                min(threat_score, 3),  # Clamp to 1-3 scale
            )
            logger.info(f"✅ VT auto-learn: {domain} added to malicious_links DB")
        except Exception as e:
            logger.error(f"Failed to auto-learn domain {domain}: {e}")


# ══════════════════════════════════════════════════════════════════
#  Cache Management (used by admin commands)
# ══════════════════════════════════════════════════════════════════


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
