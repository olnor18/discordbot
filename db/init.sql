CREATE TABLE IF NOT EXISTS users (discordId VARCHAR UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
