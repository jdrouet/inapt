use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};

fn main() -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 4096)?;
    let public_key = private_key.to_public_key();

    let private_pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    let public_pem = public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    print!("{}", &*private_pem);
    print!("{public_pem}");

    Ok(())
}
