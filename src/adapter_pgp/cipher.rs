use anyhow::Context;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use std::io::BufReader;

use crate::domain::prelude::PGPCipher;

impl PGPCipher for super::PGPClient {
    fn sign(&self, data: &str) -> anyhow::Result<String> {
        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message)
                .kind(sequoia_openpgp::armor::Kind::Signature)
                .build()
                .context("unable to build armored message")?;

            let mut signer = Signer::new(message, self.keypair.clone())
                .context("unable to create signer")?
                .detached()
                .build()
                .context("unable to create detached signer")?;

            let mut reader = BufReader::new(data.as_bytes());
            std::io::copy(&mut reader, &mut signer).context("unable to copy data to signer")?;
            signer.finalize().context("unable to finalize")?;
        }
        Ok(String::from_utf8_lossy(&sink).to_string())
    }

    fn sign_cleartext(&self, data: &str) -> anyhow::Result<String> {
        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);
            // Cleartext mode emits the full Cleartext Signature Framework
            // document and does its own ASCII armoring, so do NOT wrap it in
            // an Armorer (unlike the detached `sign` path).
            let mut signer = Signer::new(message, self.keypair.clone())
                .context("unable to create signer")?
                .cleartext()
                .build()
                .context("unable to create cleartext signer")?;

            let mut reader = BufReader::new(data.as_bytes());
            std::io::copy(&mut reader, &mut signer).context("unable to copy data to signer")?;
            signer.finalize().context("unable to finalize")?;
        }
        Ok(String::from_utf8_lossy(&sink).to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::parse::stream::{
        DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
        VerifierBuilder,
    };
    use sequoia_openpgp::policy::StandardPolicy;

    use crate::domain::prelude::PGPCipher;

    struct Helper<'a> {
        cert: &'a sequoia_openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(
            &mut self,
            _ids: &[sequoia_openpgp::KeyHandle],
        ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
            let mut good = false;
            for layer in structure.into_iter() {
                if let MessageLayer::SignatureGroup { results } = layer {
                    for r in results {
                        if r.is_ok() {
                            good = true;
                        }
                    }
                }
            }
            if good {
                Ok(())
            } else {
                anyhow::bail!("no valid signature")
            }
        }
    }

    #[test]
    fn should_produce_verifiable_cleartext_signed_document() {
        let (cert, _) = CertBuilder::new()
            .set_validity_period(None)
            .add_signing_subkey()
            .generate()
            .unwrap();

        let policy = StandardPolicy::new();
        let key = cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .unwrap();
        let keypair = key.key().clone().into_keypair().unwrap();
        let client = super::super::PGPClient { keypair };

        let mut body = String::from(
            "Origin: inapt\nLabel: inapt\nSuite: stable\nComponents: main\n-leading dash line\n",
        );
        for i in 0..500 {
            body.push_str(&format!("Package-{i}: 0123456789abcdef0123456789abcdef\n"));
        }
        let body = body.as_str();

        let out = client.sign_cleartext(body).unwrap();

        assert!(out.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(out.contains("Hash:"));
        assert!(out.contains("-----BEGIN PGP SIGNATURE-----"));

        let mut verifier = VerifierBuilder::from_bytes(out.as_bytes())
            .unwrap()
            .with_policy(&policy, None, Helper { cert: &cert })
            .unwrap();
        let mut recovered = Vec::new();
        verifier.read_to_end(&mut recovered).unwrap();
        assert_eq!(String::from_utf8(recovered).unwrap(), body);
    }

    #[test]
    fn should_produce_verifiable_detached_signature() {
        let (cert, _) = CertBuilder::new()
            .set_validity_period(None)
            .add_signing_subkey()
            .generate()
            .unwrap();

        let policy = StandardPolicy::new();
        let key = cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .next()
            .unwrap();
        let keypair = key.key().clone().into_keypair().unwrap();
        let client = super::super::PGPClient { keypair };

        let mut body = String::from(
            "Origin: inapt\nLabel: inapt\nSuite: stable\nComponents: main\n-leading dash line\n",
        );
        for i in 0..500 {
            body.push_str(&format!("Package-{i}: 0123456789abcdef0123456789abcdef\n"));
        }
        let body = body.as_str();

        let sig = client.sign(body).unwrap();

        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(sig.contains("-----END PGP SIGNATURE-----"));

        let mut verifier = DetachedVerifierBuilder::from_bytes(sig.as_bytes())
            .unwrap()
            .with_policy(&policy, None, Helper { cert: &cert })
            .unwrap();
        verifier.verify_bytes(body.as_bytes()).unwrap();
    }
}
