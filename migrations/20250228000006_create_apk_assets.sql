-- Create table for storing .apk assets and their extracted metadata
CREATE TABLE apk_assets (
    id INTEGER PRIMARY KEY,  -- GitHub asset_id
    release_id INTEGER NOT NULL,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    filename TEXT NOT NULL,
    url TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT,
    -- Extracted package metadata (from .PKGINFO)
    pkg_name TEXT NOT NULL,
    pkg_version TEXT NOT NULL,
    pkg_architecture TEXT NOT NULL,
    pkg_installed_size INTEGER NOT NULL,
    pkg_description TEXT NOT NULL,
    pkg_url TEXT NOT NULL,
    pkg_license TEXT NOT NULL,
    pkg_origin TEXT,
    pkg_maintainer TEXT,
    pkg_build_date INTEGER,
    pkg_dependencies TEXT NOT NULL,  -- JSON array
    pkg_provides TEXT NOT NULL,      -- JSON array
    pkg_datahash TEXT,
    FOREIGN KEY (release_id) REFERENCES github_releases(id)
);

CREATE INDEX idx_apk_assets_release ON apk_assets(release_id);
CREATE INDEX idx_apk_assets_arch ON apk_assets(pkg_architecture);
