use crate::internal::crypto::keys::SerializableKeypair;

type EncapsulationError = ();
pub trait DecapsulationKey<K, C>: SerializableKeypair + EncapsulationKey<K, C> {
    /**
     * Decapsulate an given ciphertext into the shared key
     */
    fn decapsulate(&self, ciphertext: C) -> Result<K, EncapsulationError>;
    fn new_encapsulation_key(&self) -> Result<Box<dyn EncapsulationKey<K, C>>, EncapsulationError>;
}

pub trait EncapsulationKey<K, C>: SerializableKeypair {
    /**
     * Derive a random shared key, and it's ciphertext.
     */
    fn derive(&self) -> Result<(K, C), EncapsulationError>;
}

pub mod mlkem768 {
    use libcrux_ml_kem::mlkem768::{self, MlKem768KeyPair, MlKem768PublicKey};
    use rand::{SeedableRng, TryRng};

    use crate::internal::crypto::{
        PrivateBytes,
        kem::{DecapsulationKey, EncapsulationError, EncapsulationKey},
        keys::{Keypair, SerializableKeypair},
        random::random_bytes,
    };

    pub type SharedKey = [u8; 32];
    pub type Ciphertext = [u8; 1088];

    pub type PublicKeyBytes = [u8; 1184];
    pub type PrivateKeyBytes = [u8; 2400];

    pub fn generate_keypair() -> Result<PrivateKey, EncapsulationError> {
        let mut randomness = [0; 64];
        random_bytes(&mut randomness).map_err(|_| ())?;
        Ok(PrivateKey {
            kp: mlkem768::generate_key_pair(randomness),
        })
    }

    mod tests {
        use crate::internal::crypto::kem::{
            DecapsulationKey, EncapsulationKey,
            mlkem768::{PrivateKey, generate_keypair},
        };

        #[test]
        fn create_and_use_keypair() {
            let kp: PrivateKey = generate_keypair().unwrap();
            let (secret, ciphertext) = kp.derive().unwrap();

            let secret_decrypted = kp.decapsulate(ciphertext).unwrap();
            assert_eq!(secret, secret_decrypted)
        }
    }

    pub struct PublicKey {
        pbk: MlKem768PublicKey,
    }

    impl SerializableKeypair for PublicKey {
        fn serialize(&self) -> crate::internal::crypto::keys::Keypair {
            return Keypair::new_public(&self.pbk.as_slice().clone());
        }

        fn deserialize(bytes: crate::internal::crypto::keys::Keypair) -> Option<Self>
        where
            Self: Sized,
        {
            if bytes.public_key.len() != 1184 {
                return None;
            }
            let mut new: PublicKeyBytes = [0; 1184];
            new.copy_from_slice(&bytes.public_key.as_slice());
            Some(PublicKey { pbk: new.into() })
        }
    }

    impl EncapsulationKey<SharedKey, Ciphertext> for PublicKey {
        fn derive(&self) -> Result<(SharedKey, Ciphertext), super::EncapsulationError> {
            let mut randomness: SharedKey = [0; 32];
            if random_bytes(&mut randomness).is_err() {
                return Err(());
            }
            let (ct, sk) = mlkem768::encapsulate(&self.pbk, randomness);
            let sk: SharedKey = sk;
            let ct: Ciphertext = ct.as_slice().clone();
            Ok((sk, ct))
        }
    }

    pub struct PrivateKey {
        kp: MlKem768KeyPair,
    }

    impl SerializableKeypair for PrivateKey {
        fn serialize(&self) -> crate::internal::crypto::keys::Keypair {
            let mut privatekey: PrivateKeyBytes = self.kp.private_key().clone().into();
            let publickey: PublicKeyBytes = self.kp.public_key().clone().into();
            Keypair::new_private(&mut privatekey, &publickey)
        }

        fn deserialize(bytes: crate::internal::crypto::keys::Keypair) -> Option<Self>
        where
            Self: Sized,
        {
            match bytes.private_key {
                Some(pk) => {
                    if pk.bytes.len() != 2400 || bytes.public_key.len() != 1184 {
                        return None;
                    }
                    let mut privatekey: PrivateKeyBytes = [0; 2400];
                    privatekey.clone_from_slice(&pk.get_bytes());
                    let mut publickey: PublicKeyBytes = [0; 1184];
                    publickey.clone_from_slice(&bytes.public_key);
                    Some(Self {
                        kp: MlKem768KeyPair::new(privatekey, publickey),
                    })
                }
                None => return None,
            }
        }
    }

    impl DecapsulationKey<SharedKey, Ciphertext> for PrivateKey {
        fn decapsulate(
            &self,
            ciphertext: Ciphertext,
        ) -> Result<SharedKey, super::EncapsulationError> {
            Ok(mlkem768::decapsulate(
                self.kp.private_key(),
                &ciphertext.into(),
            ))
        }

        fn new_encapsulation_key(
            &self,
        ) -> Result<Box<dyn EncapsulationKey<SharedKey, Ciphertext>>, EncapsulationError> {
            Ok(Box::new(PublicKey {
                pbk: self.kp.public_key().clone(),
            }))
        }
    }

    impl EncapsulationKey<SharedKey, Ciphertext> for PrivateKey {
        fn derive(&self) -> Result<(SharedKey, Ciphertext), super::EncapsulationError> {
            let mut randomness: SharedKey = [0; 32];
            if random_bytes(&mut randomness).is_err() {
                return Err(());
            }
            let (ct, sk) = mlkem768::encapsulate(&self.kp.public_key(), randomness);
            let sk: SharedKey = sk;
            let ct: Ciphertext = ct.as_slice().clone();
            Ok((sk, ct))
        }
    }
}
