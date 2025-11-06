-- Create guestbook table
CREATE TABLE IF NOT EXISTS guestbook (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    geocache_id INTEGER NOT NULL,
    full_memo TEXT NOT NULL,
    from_address TEXT NOT NULL,
    memo_string TEXT,
    output_hash TEXT NOT NULL,
    effective_date_time DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (geocache_id) REFERENCES geocaches(id) ON DELETE CASCADE
);

-- Create index on geocache_id for fast lookups
CREATE INDEX idx_guestbook_geocache_id ON guestbook(geocache_id);

-- Create index on effective_date_time for sorting
CREATE INDEX idx_guestbook_effective_date_time ON guestbook(effective_date_time);
