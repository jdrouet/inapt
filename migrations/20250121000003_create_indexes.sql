-- Create indexes for efficient querying
CREATE INDEX idx_releases_repo ON github_releases(repo_owner, repo_name);
CREATE INDEX idx_assets_release ON deb_assets(release_id);
CREATE INDEX idx_assets_arch ON deb_assets(pkg_architecture);
