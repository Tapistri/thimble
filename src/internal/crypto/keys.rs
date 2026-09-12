use rasn::{AsnType, Decode, Decoder, Encode, types::OctetString};

use crate::internal::crypto::{KeyExchangeAlgorithm, PrivateBytes, SignatureAlgorithm};

#[derive(AsnType, Decode, Encode)]
#[rasn(choice, automatic_tags)]
#[non_exhaustive]
pub enum Algorithm {
    #[rasn(identifier = "signatureAlgorithm")]
    Signature(SignatureAlgorithm),
    #[rasn(identifier = "keyExchangeAlgorithm")]
    KeyExchange(KeyExchangeAlgorithm),
}

/**
    Represents a partially serialized set of keys,
    the private key is optional, but the public key is required
*/

pub struct Keypair {
    pub private_key: Option<PrivateBytes>,
    pub public_key: Vec<u8>,
}

impl Keypair {
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    pub fn new_public(public_key: &[u8]) -> Keypair {
        Keypair {
            private_key: None,
            public_key: public_key.into(),
        }
    }

    pub fn new_private(privatekey: &mut [u8], publickey: &[u8]) -> Keypair {
        Keypair {
            private_key: Some(PrivateBytes::new(privatekey)),
            public_key: publickey.into(),
        }
    }
}

pub trait SerializableKeypair {
    fn serialize(&self) -> Keypair;
    /**
        Deserializes the given key. Note that an `Some` value doesn't
        necessarily mean the provided bytes are a valid key.
    */
    fn deserialize(bytes: Keypair) -> Option<Self>
    where
        Self: Sized;
}
