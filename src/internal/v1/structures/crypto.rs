use rasn::AsnType;
use rasn::prelude::*;

use crate::internal::crypto::DigestAlgorithm;
use crate::internal::crypto::SignatureAlgorithm;
use crate::internal::crypto::keys::Keypair;
use crate::internal::crypto::signing::VerifyKey;
use crate::internal::crypto::signing::deserialize_signingkey;

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct Signature {
    pub algorithm: SignatureAlgorithm,
    #[rasn(identifier = "signatureValue")]
    pub signature_value: OctetString,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct Digest {
    pub algorithm: DigestAlgorithm,
    #[rasn(identifier = "digestValue")]
    pub digest_value: OctetString,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct SigningKey {
    #[rasn(identifier = "publicKey")]
    pub public_key: OctetString,
    #[rasn(identifier = "publicKeyAlgorithm")]
    pub public_key_algorithm: SignatureAlgorithm,
    #[rasn(identifier = "publicKeyFingerprint")]
    pub public_key_fingerprint: Digest,
}

impl SigningKey {
    pub fn into_verify_key(&self) -> Result<Box<dyn VerifyKey>, ()> {
        match deserialize_signingkey(
            Keypair::new_public(&self.public_key),
            &self.public_key_algorithm,
        ) {
            None => Err(()),
            Some(value) => Ok(value),
        }
    }
}
