use anyhow::Context;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, SignerMut};
use sha2::Sha256;

use crate::domain::prelude::RsaSigner;

impl RsaSigner for super::RsaClient {
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key
            .try_sign(data)
            .context("unable to sign data with RSA key")?;
        Ok(signature.to_vec())
    }

    fn key_name(&self) -> &str {
        &self.key_name
    }
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use sha2::Sha256;

    use crate::domain::prelude::RsaSigner;

    fn build_test_client() -> super::super::RsaClient {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        super::super::RsaClient {
            private_key,
            key_name: "test.rsa.pub".to_string(),
        }
    }

    #[test]
    fn should_sign_data_and_verify_signature() {
        let client = build_test_client();
        let data = b"hello world APKINDEX content";

        let signature_bytes = client.sign(data).unwrap();

        let public_key = client.private_key.to_public_key();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).unwrap();
        verifying_key.verify(data, &signature).unwrap();
    }

    #[test]
    fn should_produce_deterministic_signatures_for_same_input() {
        let client = build_test_client();
        let data = b"deterministic test data";

        let sig1 = client.sign(data).unwrap();
        let sig2 = client.sign(data).unwrap();

        // PKCS#1 v1.5 signatures are deterministic for the same key and data
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn should_return_key_name() {
        let client = build_test_client();
        assert_eq!(client.key_name(), "test.rsa.pub");
    }

    #[test]
    fn should_load_key_from_pem_and_sign() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem =
            rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, rsa::pkcs1::LineEnding::LF)
                .unwrap();

        let loaded_key = RsaPrivateKey::from_pkcs1_pem(&pem).unwrap();
        let client = super::super::RsaClient {
            private_key: loaded_key,
            key_name: "loaded.rsa.pub".to_string(),
        };

        let data = b"pem round-trip test";
        let signature_bytes = client.sign(data).unwrap();

        let public_key = private_key.to_public_key();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).unwrap();
        verifying_key.verify(data, &signature).unwrap();
    }
}
