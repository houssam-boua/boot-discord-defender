# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Proxycheck.io IP Reputation Wrapper
#  Directly from blueprint Section 8b: "Proxycheck.io Integration"
#
#  Called during web-based CAPTCHA flow when a user's IP is captured.
#  Returns: proxy, vpn, tor, residential classification.
#  Action: if type is proxy/vpn/tor → kick user + log.
# ══════════════════════════════════════════════════════════════════

import logging

import aiohttp

logger = logging.getLogger("antiraid.proxycheck")


async def check_ip(ip: str, api_key: str) -> dict:
    """
    Query the Proxycheck.io API for an IP's reputation.

    Args:
        ip:      The IP address to check.
        api_key: Proxycheck.io API key.

    Returns:
        A dict with keys like: 'proxy', 'type', 'risk', 'country', etc.
        Returns an empty dict on failure.
    """
    url = f"https://proxycheck.io/v2/{ip}?key={api_key}&vpn=1&risk=1"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                data = await resp.json()
                result = data.get(ip, {})

                logger.debug(
                    f"ProxyCheck result for {ip}: "
                    f"proxy={result.get('proxy')}, "
                    f"type={result.get('type')}, "
                    f"risk={result.get('risk')}"
                )

                return result

    except aiohttp.ClientError as e:
        logger.warning(f"ProxyCheck API request failed for {ip}: {e}")
        return {}
    except Exception as e:
        logger.error(f"ProxyCheck unexpected error: {e}")
        return {}


def is_suspicious_ip(result: dict) -> bool:
    """
    Evaluate a Proxycheck result and determine if the IP is suspicious.

    Args:
        result: The dict returned by check_ip().

    Returns:
        True if the IP is a proxy, VPN, or Tor exit node.
    """
    if not result:
        return False

    # Direct proxy flag
    if result.get("proxy") == "yes":
        return True

    # Type-based detection
    ip_type = result.get("type", "").upper()
    if ip_type in ("VPN", "TOR", "SOCKS", "SOCKS4", "SOCKS5", "INFERENCE"):
        return True

    # High risk score (0-100, threshold at 66)
    try:
        risk = int(result.get("risk", 0))
        if risk >= 66:
            return True
    except (ValueError, TypeError):
        pass

    return False
