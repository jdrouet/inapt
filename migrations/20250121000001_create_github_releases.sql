-- Create table for storing scanned GitHub releases
CREATE TABLE github_releases (
    id INTEGER PRIMARY KEY,  -- GitHub release_id
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    scanned_at TIMESTAMP NOT NULL,
    UNIQUE(repo_owner, repo_name, id)
);
