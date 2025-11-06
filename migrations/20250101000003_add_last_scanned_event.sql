-- Add last_scanned_event_id to geocaches table
ALTER TABLE geocaches ADD COLUMN last_scanned_event_id INTEGER DEFAULT 0;
