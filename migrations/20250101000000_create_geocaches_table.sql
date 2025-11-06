-- Create geocaches table
CREATE TABLE IF NOT EXISTS geocaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    latitude REAL,
    longitude REAL,
    view_key TEXT NOT NULL,
    spend_pub_key TEXT NOT NULL,
    short_id TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_short_id ON geocaches(short_id);
