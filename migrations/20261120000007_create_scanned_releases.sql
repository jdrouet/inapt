-- Track scanned releases per package format so the APT and APK syncs don't
-- skip each other's assets. github_releases stays the FK target for assets.
CREATE TABLE scanned_releases (
    kind TEXT NOT NULL,  -- 'deb' or 'apk'
    release_id INTEGER NOT NULL,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    scanned_at TIMESTAMP NOT NULL,
    PRIMARY KEY (kind, repo_owner, repo_name, release_id)
);

-- A release only counts as scanned for a format if assets of that format were
-- stored; anything else gets one rescan, which recovers previously skipped assets.
INSERT INTO scanned_releases (kind, release_id, repo_owner, repo_name, scanned_at)
SELECT DISTINCT 'deb', r.id, r.repo_owner, r.repo_name, r.scanned_at
FROM github_releases r JOIN deb_assets a ON a.release_id = r.id;

INSERT INTO scanned_releases (kind, release_id, repo_owner, repo_name, scanned_at)
SELECT DISTINCT 'apk', r.id, r.repo_owner, r.repo_name, r.scanned_at
FROM github_releases r JOIN apk_assets a ON a.release_id = r.id;
