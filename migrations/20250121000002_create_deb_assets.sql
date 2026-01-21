-- Create table for storing .deb assets and their extracted metadata
CREATE TABLE deb_assets (
    id INTEGER PRIMARY KEY,  -- GitHub asset_id
    release_id INTEGER NOT NULL,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    filename TEXT NOT NULL,
    url TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT,
    -- Extracted package metadata (from control file)
    pkg_name TEXT NOT NULL,
    pkg_version TEXT NOT NULL,
    pkg_section TEXT,
    pkg_priority TEXT NOT NULL,
    pkg_architecture TEXT NOT NULL,
    pkg_maintainer TEXT NOT NULL,
    pkg_description TEXT NOT NULL,  -- JSON array of lines
    pkg_others TEXT NOT NULL,       -- JSON object for extra fields
    -- File metadata
    file_size INTEGER NOT NULL,
    file_sha256 TEXT NOT NULL,
    FOREIGN KEY (release_id) REFERENCES github_releases(id)
);
