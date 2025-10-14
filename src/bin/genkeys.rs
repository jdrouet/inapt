use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize, types::KeyFlags};

fn main() -> anyhow::Result<()> {
    let (cert, _) = CertBuilder::new()
        .set_validity_period(None)
        .add_userid("<jeremie.drouet@gmail.com>")
        .add_subkey(
            KeyFlags::empty().set_transport_encryption().set_group_key(),
            None,
            None,
        )
        .add_signing_subkey()
        .add_certification_subkey()
        .add_storage_encryption_subkey()
        .generate()?;

    let mut output = std::io::stdout();
    cert.armored().serialize(&mut output)?;

    cert.as_tsk().armored().serialize(&mut output)?;

    Ok(())
}
