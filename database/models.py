# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Typed Data Models
#  Dataclass representations of core database tables.
#
#  Fix M-2: Establishes typed Python models to replace raw dict
#  access (row["field"]) over time.  All field types match the
#  PostgreSQL schemas in database/migrations/.
#
#  Usage (gradual migration):
#    row = await pool.fetchrow(...)
#    config = ServerConfig(**dict(row))
# ══════════════════════════════════════════════════════════════════

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ServerConfig:
    """Maps to: server_configs (001_initial_schema.sql)"""

    guild_id: int
    prefix: str = "!"
    raid_limit_count: int = 10
    raid_limit_seconds: int = 3
    log_channel_id: int | None = None
    quarantine_role_id: int | None = None
    min_account_age_hours: int = 24
    captcha_enabled: bool = True
    proxycheck_enabled: bool = False
    antinuke_enabled: bool = True
    antispam_enabled: bool = True
    max_mentions: int = 5
    spam_msg_limit: int = 5
    spam_msg_seconds: int = 2
    created_at: datetime | None = None


@dataclass
class TemporalPunishment:
    """Maps to: temporal_punishments (001_initial_schema.sql)"""

    id: int = 0
    guild_id: int = 0
    user_id: int = 0
    punishment_type: str = ""  # "ban" | "mute" | "quarantine"
    expires_at: datetime | None = None
    reason: str | None = None
    issued_by: int | None = None
    active: bool = True
    created_at: datetime | None = None


@dataclass
class AuditLog:
    """Maps to: audit_logs (002_audit_logs.sql)"""

    id: int = 0
    guild_id: int = 0
    actor_id: int | None = None
    target_id: int | None = None
    action_type: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "INFO"  # "INFO" | "WARN" | "CRITICAL"
    created_at: datetime | None = None
    hash_signature: str = ""


@dataclass
class MaliciousLink:
    """Maps to: malicious_links (001_initial_schema.sql)"""

    id: int = 0
    domain: str = ""
    threat_level: int = 1  # 1=low, 2=medium, 3=critical
    source: str | None = None  # "manual" | "auto" | "community" | "seed"
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class RiskScore:
    """Maps to: risk_scores (003_risk_scoring.sql)"""

    guild_id: int = 0
    user_id: int = 0
    account_age_score: int = 0
    vpn_flag: bool = False
    spam_velocity_score: int = 0
    link_abuse_score: int = 0
    mention_abuse_score: int = 0
    total_score: int = 0
    last_updated: datetime | None = None


@dataclass
class Whitelist:
    """Maps to: whitelists (001_initial_schema.sql)"""

    id: int = 0
    guild_id: int = 0
    entity_id: int = 0
    entity_type: str = ""  # "role" | "channel" | "user"
    added_by: int | None = None
    added_at: datetime | None = None


@dataclass
class AntiNukeWhitelist:
    """Maps to: antinuke_whitelist (005_missing_tables.sql)"""

    id: int = 0
    guild_id: int = 0
    user_id: int = 0
    added_by: int | None = None
    reason: str | None = None
    created_at: datetime | None = None


@dataclass
class CaptchaChallenge:
    """Maps to: captcha_challenges (005_missing_tables.sql)"""

    id: int = 0
    guild_id: int = 0
    user_id: int = 0
    answer: str = ""
    attempts: int = 0
    created_at: datetime | None = None
    expires_at: datetime | None = None
    completed: bool = False


@dataclass
class ServerSnapshot:
    """Maps to: server_snapshots (003_risk_scoring.sql)"""

    id: int = 0
    guild_id: int = 0
    snapshot_type: str = ""  # "channels" | "roles" | "permissions"
    data: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
