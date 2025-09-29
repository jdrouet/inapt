mod deb;
mod file;

#[derive(Clone, Debug)]
pub struct DebReader;

impl crate::domain::prelude::DebMetadataExtractor for DebReader {
    async fn extract_metadata(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<crate::domain::entity::PackageMetadata> {
        Ok(crate::domain::entity::PackageMetadata {
            control: deb::from_path(path)?,
            file: file::from_path(path)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{adapter_deb::DebReader, domain::prelude::DebMetadataExtractor};

    #[tokio::test]
    async fn should_extract_metadata() {
        let current = std::env::current_dir().unwrap();
        let path = current.join("resources").join("curl_8.14.1-2_amd64.deb");
        let res = DebReader.extract_metadata(&path).await.unwrap();
        assert_eq!(res.control.package, "curl");
        assert_eq!(res.control.version, "8.14.1-2");
        assert_eq!(res.control.section, "web");
        assert_eq!(res.control.architecture, "amd64");
        similar_asserts::assert_eq!(
            res.control.description.join("\n"),
            r#"command line tool for transferring data with URL syntax
curl is a command line tool for transferring data with URL syntax, supporting
DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3,
POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
.
curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form
based upload, proxies, cookies, user+password authentication (Basic, Digest,
NTLM, Negotiate, kerberos...), file transfer resume, proxy tunneling and a
busload of other useful tricks."#
        );
    }
}
