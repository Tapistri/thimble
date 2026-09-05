use rasn::{AsnType, Decode, Decoder, Encode, types::OctetString};

use crate::internal::crypto::{KeyExchangeAlgorithm, SignatureAlgorithm};

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct Keystore {
    #[rasn(identifier = "keyAlgorithm")]
    key_algorithm: Algorithm,
    #[rasn(identifier = "publicKey")]
    public_key: OctetString,
    #[rasn(identifier = "privateKey")]
    private_key: Option<OctetString>,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(choice, automatic_tags)]
#[non_exhaustive]
pub enum Algorithm {
    #[rasn(identifier = "signatureAlgorithm")]
    Signature(SignatureAlgorithm),
    #[rasn(identifier = "keyExchangeAlgorithm")]
    KeyExchange(KeyExchangeAlgorithm),
}
