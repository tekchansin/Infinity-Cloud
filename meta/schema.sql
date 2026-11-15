-- Infinity recipe server: shared answers so every Mac does not ask MusicBrainz / Wikipedia the same thing.
CREATE TABLE IF NOT EXISTS answers (
  kind TEXT NOT NULL,      -- artist
  key TEXT NOT NULL,       -- normalized name
  lang TEXT NOT NULL,      -- the UI language asked for (en, th, ja, zh, ko)
  json TEXT NOT NULL,
  fetched INTEGER NOT NULL, -- ms
  PRIMARY KEY (kind, key, lang)
);
CREATE TABLE IF NOT EXISTS throttle (name TEXT PRIMARY KEY, at INTEGER NOT NULL);  -- MusicBrainz: one call a second, all users
