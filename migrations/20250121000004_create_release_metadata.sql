-- Create table for storing release metadata history
CREATE TABLE release_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    origin TEXT NOT NULL,
    label TEXT NOT NULL,
    suite TEXT NOT NULL,
    version TEXT NOT NULL,
    codename TEXT NOT NULL,
    date TIMESTAMP NOT NULL,
    components TEXT NOT NULL,  -- JSON array of component names
    description TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_release_metadata_created_at ON release_metadata(created_at DESC);
