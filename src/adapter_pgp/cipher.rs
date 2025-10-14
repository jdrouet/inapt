use anyhow::Context;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use std::io::{BufReader, BufWriter};

use crate::domain::prelude::PGPCipher;

impl PGPCipher for super::PGPClient {
    fn sign(&self, data: &str) -> anyhow::Result<String> {
        let mut sink = BufWriter::new(Vec::new());

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

        Ok(String::from_utf8_lossy(sink.buffer()).to_string())
    }
}
