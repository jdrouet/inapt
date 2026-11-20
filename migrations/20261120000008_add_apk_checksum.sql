-- APKINDEX `C:` needs the SHA-1 of each package's control stream, which can
-- only be computed from the file. Drop cached APK packages and their scan
-- marks so the next sync downloads them again and stores the checksum.
DELETE FROM apk_assets;
DELETE FROM scanned_releases WHERE kind = 'apk';

ALTER TABLE apk_assets ADD COLUMN pkg_checksum TEXT NOT NULL DEFAULT '';
