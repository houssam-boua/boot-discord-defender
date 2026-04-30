-- ══════════════════════════════════════════════════════════════
--  004_seed_phishing_domains.sql
--  Populates the baseline phishing domain threat list.
--  Run once on initial deployment — safe to re-run (ON CONFLICT DO NOTHING).
--  Source: Blueprint Section 8.2
-- ══════════════════════════════════════════════════════════════

INSERT INTO malicious_links (domain, threat_level, source) VALUES
  ('discord-nitro.gift',    3, 'seed'),
  ('free-nitro.ru',         3, 'seed'),
  ('discordapp.gift',       3, 'seed'),
  ('discord.gift.ru',       3, 'seed'),
  ('nitro-discord.com',     3, 'seed'),
  ('dlscord.com',           3, 'seed'),
  ('discrod.com',           3, 'seed'),
  ('discordnitro.online',   3, 'seed'),
  ('discordapp.io',         2, 'seed'),
  ('discord.rip',           3, 'seed'),
  ('discord-giveaway.com',  3, 'seed'),
  ('discordnitro.gift',     3, 'seed'),
  ('qr-discord.com',        3, 'seed'),
  ('discord-boost.net',     2, 'seed'),
  ('discord-gift.org',      3, 'seed'),
  ('free-discord.ru',       3, 'seed'),
  ('discordapp.co',         2, 'seed'),
  ('nitro.gift.ru',         3, 'seed'),
  ('discordskins.com',      2, 'seed'),
  ('free-steam.ru',         3, 'seed'),
  ('steamgift.ru',          3, 'seed'),
  ('steamgifts.ru',         3, 'seed'),
  ('steamtrade.ru',         2, 'seed'),
  ('epicgames.gift',        3, 'seed'),
  ('csgo-skins.ru',         2, 'seed'),
  ('tradeit.ru',            2, 'seed'),
  ('skinport.gift',         3, 'seed')
ON CONFLICT (domain) DO NOTHING;
