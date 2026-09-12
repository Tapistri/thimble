trait SymmetricKey<const K: usize, const IV: usize> {
    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; IV]), SymmetricError>;
    fn decrypt(&self, ciphertext: &[u8], iv: [u8; IV]) -> Result<Vec<u8>, SymmetricError>;
    fn as_bytes(&self) -> Result<[u8; K], SymmetricError>;
    fn from_bytes(key: [u8; K]) -> Result<Box<Self>, SymmetricError>;
}

type SymmetricError = ();

mod aes256gcm {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    use crate::internal::crypto::{
        PrivateBytes,
        random::{self, random_bytes},
        symmetric::{SymmetricError, SymmetricKey},
    };

    struct AESKey {
        key: PrivateBytes,
        instance: Aes256Gcm,
    }

    mod test {
        use crate::internal::crypto::symmetric::{SymmetricKey, aes256gcm::new_key};

        #[test]
        fn symmetric_encryption_test() {
            let key = new_key().unwrap();
            let content = b"Hawwo Kazaiiii!!!!";
            let (ct, iv) = key.encrypt(content).unwrap();
            assert_ne!(content, ct.as_slice());
            let pt = key.decrypt(&ct, iv).unwrap();
            assert_eq!(pt, content)
        }
    }

    fn new_key() -> Result<AESKey, SymmetricError> {
        let mut key = [0u8; 32];
        if random_bytes(&mut key).is_err() {
            return Err(());
        }
        match AESKey::from_bytes(key) {
            Ok(boxed) => return Ok(*boxed),
            Err(_) => Err(()),
        }
    }

    impl SymmetricKey<32, 12> for AESKey {
        fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), SymmetricError> {
            let mut nonce = [0u8; 12];
            if (random::random_bytes(&mut nonce)).is_err() {
                return Err(());
            }
            match self.instance.encrypt(Nonce::from(nonce).as_ref(), data) {
                Ok(ct) => Ok((ct, nonce)),
                Err(_) => return Err(()),
            }
        }

        fn decrypt(&self, ciphertext: &[u8], iv: [u8; 12]) -> Result<Vec<u8>, SymmetricError> {
            match self.instance.decrypt(Nonce::from(iv).as_ref(), ciphertext) {
                Ok(pt) => Ok(pt),
                Err(_) => return Err(()),
            }
        }

        fn as_bytes(&self) -> Result<[u8; 32], SymmetricError> {
            let mut key = [0u8; 32];
            key.copy_from_slice(self.key.get_bytes().as_slice());
            Ok(key)
        }

        fn from_bytes(key: [u8; 32]) -> Result<Box<Self>, SymmetricError> {
            let mut tkey = key.clone();
            Ok(Box::new(Self {
                key: PrivateBytes::new(&mut tkey),
                instance: Aes256Gcm::new(&key.into()),
            }))
        }
    }
}

mod aes256gcmsiv {
    use aes_gcm::{KeyInit, aead::Aead};
    use aes_gcm_siv::{Aes256GcmSiv, Nonce};

    use crate::internal::crypto::{
        PrivateBytes,
        random::{self, random_bytes},
        symmetric::{SymmetricError, SymmetricKey},
    };

    struct AESSivKey {
        key: PrivateBytes,
        instance: Aes256GcmSiv,
    }

    mod test {
        use crate::internal::crypto::symmetric::{SymmetricKey, aes256gcmsiv::new_key};

        #[test]
        fn symmetric_encryption_test() {
            let key = new_key().unwrap();
            let content = b"Hawwo Kazaiiii!!!! :3";
            let (ct, iv) = key.encrypt(content).unwrap();
            assert_ne!(content, ct.as_slice());
            let pt = key.decrypt(&ct, iv).unwrap();
            assert_eq!(pt, content)
        }
    }

    fn new_key() -> Result<AESSivKey, SymmetricError> {
        let mut key = [0u8; 32];
        if random_bytes(&mut key).is_err() {
            return Err(());
        }
        match AESSivKey::from_bytes(key) {
            Ok(boxed) => return Ok(*boxed),
            Err(_) => Err(()),
        }
    }

    impl SymmetricKey<32, 12> for AESSivKey {
        fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), SymmetricError> {
            let mut nonce = [0u8; 12];
            if (random::random_bytes(&mut nonce)).is_err() {
                return Err(());
            }
            match self.instance.encrypt(Nonce::from(nonce).as_ref(), data) {
                Ok(ct) => Ok((ct, nonce)),
                Err(_) => return Err(()),
            }
        }

        fn decrypt(&self, ciphertext: &[u8], iv: [u8; 12]) -> Result<Vec<u8>, SymmetricError> {
            match self.instance.decrypt(Nonce::from(iv).as_ref(), ciphertext) {
                Ok(pt) => Ok(pt),
                Err(_) => return Err(()),
            }
        }

        fn as_bytes(&self) -> Result<[u8; 32], SymmetricError> {
            let mut key = [0u8; 32];
            key.copy_from_slice(self.key.get_bytes().as_slice());
            Ok(key)
        }

        fn from_bytes(key: [u8; 32]) -> Result<Box<Self>, SymmetricError> {
            let mut tkey = key.clone();
            Ok(Box::new(Self {
                key: PrivateBytes::new(&mut tkey),
                instance: Aes256GcmSiv::new(&key.into()),
            }))
        }
    }
}
