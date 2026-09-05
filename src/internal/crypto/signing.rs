// struct SigningKey {}

use libcrux_ml_kem::mlkem768::avx2::unpacked::public_key;

use crate::internal::crypto::{PrivateBytes, SignatureAlgorithm, ZeroedDropBytes, keys::Keystore};

#[derive(Debug)]
pub enum SignatureError {
    Unknown,
    InvalidKey,
    InvalidSignature,
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

pub trait SigningKey: SerializableKeypair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignatureError>;
    fn new_verify_key(&self) -> Result<Box<dyn VerifyKey>, SignatureError>;
}

pub trait VerifyKey: SerializableKeypair {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignatureError>;
}

pub fn deserialize_verifykey(
    keys: Keypair,
    algorithm: SignatureAlgorithm,
) -> Option<Box<dyn VerifyKey>> {
    match algorithm {
        SignatureAlgorithm::FnDsa512Draft => {
            Some(Box::new(fndsa512::PublicKey::deserialize(keys)?))
        }
    }
}

pub fn deserialize_signingkey(
    keys: Keypair,
    algorithm: &SignatureAlgorithm,
) -> Option<Box<dyn VerifyKey>> {
    if !keys.has_private_key() {
        return None;
    }
    match algorithm {
        SignatureAlgorithm::FnDsa512Draft => {
            Some(Box::new(fndsa512::PrivateKey::deserialize(keys)?))
        }
    }
}

mod test {
    use crate::internal::crypto::{
        PrivateBytes,
        signing::{SerializableKeypair, SigningKey, VerifyKey, fndsa512},
    };

    #[test]
    fn dsa_test() {
        let key = fndsa512::new_keypair().unwrap();
        let message = b"Hawwo Kazani!!";
        let signature = key.sign(message).unwrap();
        let valid = key.verify(message, signature.as_slice()).unwrap();
        assert!(valid);
        let wrong_message = b"Kazani is evil...";
        let invalid = key.verify(wrong_message, signature.as_slice()).unwrap();
        assert!(!invalid)
    }
    #[test]
    fn private_bytes_test() {
        let message = b"Nebo is silly";
        let obscured = PrivateBytes::new(&mut message.to_vec().clone());
        dbg!(message);
        dbg!(obscured.get_bytes().as_slice());
        assert_ne!(message, obscured.bytes.as_slice());
        assert_eq!(message, obscured.get_bytes().as_slice());
    }

    #[test]
    fn dsa_round_trip_privatekey() {
        let key = fndsa512::new_keypair().unwrap();
        let keypair = key.serialize();
        let new_key = fndsa512::PrivateKey::deserialize(keypair).unwrap();
        let message = b"Hawwo Kazani!!";
        let original_signature = key.sign(message).unwrap();
        let new_signature = new_key.sign(message).unwrap();
        let verify_orignal_with_new = new_key
            .verify(message, original_signature.as_slice())
            .unwrap();
        let verify_new_with_original = key.verify(message, new_signature.as_slice()).unwrap();
        assert!(verify_new_with_original);
        assert!(verify_orignal_with_new);
    }

    #[test]
    fn dsa_round_trip_publickey() {
        let key = fndsa512::new_keypair().unwrap();
        let keypair = key.serialize();
        let message = "Kuki is \u{1f3f3}\u{200d}\u{26a7}!!!".as_bytes();
        let signature = key.sign(message).unwrap();
        assert!(key.verify(message, signature.as_slice()).unwrap());
        let public_keypair = key.new_verify_key().unwrap().serialize();
        assert!(public_keypair.private_key.is_none());
        let public_key = fndsa512::PublicKey::deserialize(public_keypair);
        assert!(
            public_key
                .unwrap()
                .verify(message, signature.as_slice())
                .unwrap()
        );
    }
}

pub mod fndsa512 {
    use falcon::{DomainSeparation, FalconError, FnDsaKeyPair, FnDsaSignature};

    pub fn new_keypair() -> Result<PrivateKey, ()> {
        let kp = FnDsaKeyPair::generate(9).map_err(|_| ())?;
        Ok(PrivateKey { kp: kp })
    }

    fn sign_with_keypair(data: &[u8], kp: &FnDsaKeyPair) -> Result<Vec<u8>, ()> {
        // let kp = FnDsaKeyPair::from_keys(private_key, public_key);
        let sig = kp.sign(data, &DomainSeparation::None).map_err(|_| ())?;
        Ok(sig.into_bytes())
    }

    fn sign(data: &[u8], private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ()> {
        let kp = FnDsaKeyPair::from_keys(private_key, public_key).map_err(|_| ())?;
        let sig = kp.sign(data, &DomainSeparation::None).map_err(|_| ())?;
        Ok(sig.into_bytes())
    }

    fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        FnDsaSignature::verify(signature, public_key, data, &DomainSeparation::None).is_ok()
    }

    use crate::internal::crypto::{
        PrivateBytes, ZeroedDropBytes,
        signing::{Keypair, SerializableKeypair, SignatureError, SigningKey, VerifyKey},
    };

    pub struct PublicKey {
        key: Vec<u8>,
    }

    impl SerializableKeypair for PublicKey {
        fn serialize(&self) -> super::Keypair {
            super::Keypair {
                private_key: None,
                public_key: self.key.clone(),
            }
        }

        fn deserialize(keys: Keypair) -> Option<Self> {
            let new = keys.public_key;
            Some(Self { key: new })
        }
    }

    impl VerifyKey for PublicKey {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignatureError> {
            Ok(verify(data, signature, &self.key))
        }
    }

    pub struct PrivateKey {
        kp: FnDsaKeyPair,
    }

    impl VerifyKey for PrivateKey {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignatureError> {
            Ok(verify(data, signature, &self.kp.public_key()))
        }
    }

    impl SerializableKeypair for PrivateKey {
        fn deserialize(keys: super::Keypair) -> Option<Self> {
            match keys.private_key {
                None => None,
                Some(pvk) => match FnDsaKeyPair::from_keys(&pvk.get_bytes(), &keys.public_key) {
                    Ok(value) => Some(PrivateKey { kp: value }),
                    Err(a) => {
                        dbg!(a);
                        None
                    }
                },
            }
        }

        fn serialize(&self) -> super::Keypair {
            Keypair {
                private_key: Some(PrivateBytes::new(&mut self.kp.private_key().to_vec())),
                public_key: self.kp.public_key().to_vec(),
            }
        }
    }

    impl SigningKey for PrivateKey {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignatureError> {
            sign_with_keypair(data, &self.kp).map_err(|e| SignatureError::Unknown)
        }

        fn new_verify_key(&self) -> Result<Box<dyn VerifyKey>, SignatureError> {
            let pk = self.kp.public_key();
            Ok(Box::new(PublicKey { key: pk.to_vec() }))
        }
    }
}
