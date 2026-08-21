use std::collections::BTreeMap;

use reproit_core::{Error, canonical, crypto::SecretKey, identity::Digest, model::UploadEnvelope};

use crate::seal::{OpenedCapture, open_capture};

pub struct KeptCapture {
    ciphertext: BTreeMap<Digest, Vec<u8>>,
    envelope_bytes: Vec<u8>,
}

impl KeptCapture {
    pub fn copy_verified(
        envelope_bytes: &[u8],
        ciphertext: &BTreeMap<Digest, Vec<u8>>,
        verification_key: &[u8; 32],
        occurrence_key: &SecretKey,
    ) -> Result<Self, Error> {
        let envelope: UploadEnvelope = canonical::parse_strict(envelope_bytes)?;
        open_capture(&envelope, verification_key, occurrence_key, ciphertext)?;
        Ok(Self {
            ciphertext: ciphertext.clone(),
            envelope_bytes: envelope_bytes.to_vec(),
        })
    }

    pub fn open(
        &self,
        verification_key: &[u8; 32],
        occurrence_key: &SecretKey,
    ) -> Result<OpenedCapture, Error> {
        let envelope: UploadEnvelope = canonical::parse_strict(&self.envelope_bytes)?;
        open_capture(
            &envelope,
            verification_key,
            occurrence_key,
            &self.ciphertext,
        )
    }

    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    pub fn ciphertext(&self) -> &BTreeMap<Digest, Vec<u8>> {
        &self.ciphertext
    }
}
