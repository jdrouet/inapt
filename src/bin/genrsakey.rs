use rsa::PrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};

fn main() -> anyhow::Result<()> {
    let mut rng = getrandom::SysRng;
    let private_key = PrivateKey::new(&mut rng, 4096)?;
    let public_key = private_key.to_public_key();

    let private_pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    let public_pem = public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;

    print!("{}", *private_pem);
    print!("{public_pem}");

    Ok(())
}
