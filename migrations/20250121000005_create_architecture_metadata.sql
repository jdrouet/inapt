-- Create table for storing architecture metadata (computed hashes)
CREATE TABLE architecture_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_metadata_id INTEGER NOT NULL,
    name TEXT NOT NULL,  -- e.g., "amd64", "arm64"
    plain_md5 TEXT NOT NULL,
    plain_sha256 TEXT NOT NULL,
    plain_size INTEGER NOT NULL,
    compressed_md5 TEXT NOT NULL,
    compressed_sha256 TEXT NOT NULL,
    compressed_size INTEGER NOT NULL,
    FOREIGN KEY (release_metadata_id) REFERENCES release_metadata(id)
);

CREATE INDEX idx_architecture_metadata_release ON architecture_metadata(release_metadata_id);
