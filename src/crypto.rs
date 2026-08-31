use crate::certificates::KeyExchangeAlgorithm::MlKem768;

pub trait SigningAlgorithm {
    fn new_keypair() -> Result<Keypair, CryptoError>;

    fn sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool;
}

// key -> ()

pub enum CryptoError {
    Unsupported, // Operation is unsupported by the algorithm
    InvalidCiphertext, // Given ciphertext is invalid or corrupted
    InvalidKey, // Key is in an invalid format or corrupted
    SystemError // Some other system error occurred (e.g. RNG failure)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyType {
    MLKEM768,
    FNDSA512
}

pub struct Keypair {
    private_key: PrivateKey,
    public_key: PublicKey
}

impl Keypair {
    pub fn new(private_key: &[u8], public_key: &[u8], algorithm: KeyType) -> Self {
        Keypair {
            private_key: PrivateKey { bytes: private_key.to_vec(), algorithm: algorithm.clone()},
            public_key: PublicKey { bytes: public_key.to_vec(), algorithm }
        }
    }

    pub fn get_algorithm(&self) -> &KeyType {
        debug_assert_eq!(&self.private_key.algorithm, &self.public_key.algorithm);
        &self.private_key.algorithm
    }

    pub fn get_public_key_bytes(&self) -> &[u8] {
        &self.public_key.bytes
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn get_private_key_bytes(&self) -> &[u8] {
        &self.private_key.bytes
    }
}

pub struct PublicKey {
    algorithm: KeyType,
    bytes: Vec<u8>
}

pub struct PrivateKey {
    algorithm: KeyType,
    bytes: Vec<u8>
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

type SharedSecret = Vec<u8>;
type Ciphertext = Vec<u8>;

pub trait KeyExchangeAlgorithm {
    // (public, private)
    fn new_keypair() -> Result<Keypair, CryptoError>;

    fn supports_mutual_secrets() -> bool;

    fn get_shared_key_size() -> usize;
    // public_key -> (shared_secret, ciphertext)
    fn derive_secret(public_key: &PublicKey) -> Result<(SharedSecret, Ciphertext), CryptoError>;
    fn derive_mutual_secrets(public_key: &[&PublicKey]) -> Result<(SharedSecret, Ciphertext), CryptoError>;
    
    fn extract_secret(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<SharedSecret, CryptoError>; 
}

pub trait DigestAlgorithm {
    fn digest(data: &[u8]) -> Vec<u8>;  
}

mod sha256 {
    use sha2::{Sha256, Digest};
    use crate::crypto::DigestAlgorithm;

    pub struct SHA256 {}

    impl DigestAlgorithm for SHA256 {
        fn digest(data: &[u8]) -> Vec<u8> {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
    }
}

mod FNDSA512rs {
    use falcon::prelude::*;
    use rand::{SeedableRng, TryRng, rngs::StdRng};
    use crate::crypto::*;
    pub struct FNDSA512 {}

    impl FNDSA512 {
        fn random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
            let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).map_err(|e| CryptoError::SystemError)?;
            rng.try_fill_bytes(buffer).map_err(|e| CryptoError::SystemError)?;
            Ok(())
        }

        
    }

    impl SigningAlgorithm for FNDSA512 {
        fn new_keypair() -> Result<Keypair, CryptoError> {
            let kp = FnDsaKeyPair::generate(9).map_err(| e| CryptoError::SystemError)?;
            let sk = kp.private_key();
            let pk = kp.public_key();
            let kp = Keypair::new(sk, pk, KeyType::FNDSA512);
            Ok(kp)
        }
    
        fn sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let kp = FnDsaKeyPair::from_private_key(private_key).map_err(|_| CryptoError::InvalidKey)?;
            let sig = kp.sign(data, &DomainSeparation::None).map_err(|_| CryptoError::SystemError)?;
            // let kp = FnDsaKeyPair::from_private_key(private_key).unwrap();
            // let sig = kp.sign(data, &DomainSeparation::None).unwrap();

            Ok(sig.into_bytes())
        }
    
        fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
            FnDsaSignature::verify(signature, public_key, data, &DomainSeparation::None).is_ok()
        }
    }
}


mod mlkem {
    pub struct MLKEM768 {}
    use libcrux_ml_kem::{mlkem768::MlKem768PublicKey, *};
    use libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;
    use rand::{SeedableRng, TryRng};
    use crate::crypto::*;

    fn random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
        let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).map_err(|e| CryptoError::SystemError)?;
        rng.try_fill_bytes(buffer).map_err(|e| CryptoError::SystemError)?;
        Ok(())
    }

    impl MLKEM768 {

    }

    impl KeyExchangeAlgorithm for MLKEM768 {
        fn derive_mutual_secrets(_public_key: &[&PublicKey]) -> Result<(SharedSecret, Ciphertext), CryptoError> {
            Err(CryptoError::Unsupported)
        }
        
        fn new_keypair() -> Result<Keypair, CryptoError> {
            let mut seed = [0u8; KEY_GENERATION_SEED_SIZE];
            random_bytes(&mut seed)?;
            let keypair = mlkem::mlkem768::generate_key_pair(seed);
            let private_key = keypair.sk().to_vec();
            let pub_key = keypair.pk().to_vec();
            Ok(Keypair::new(&private_key, &pub_key, KeyType::MLKEM768))
        }
        
        fn supports_mutual_secrets() -> bool {

            false
        }
        
        fn get_shared_key_size() -> usize {
            mlkem::SHARED_SECRET_SIZE
        }
        
        fn derive_secret(public_key: &PublicKey) -> Result<(SharedSecret, Ciphertext), CryptoError> {
            let key = MlKem768PublicKey::try_from(public_key.bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
            if !mlkem768::validate_public_key(&key) {
                return Err(CryptoError::InvalidKey);
            } else {
                let mut buffer = [0u8; mlkem::SHARED_SECRET_SIZE];
                random_bytes(&mut buffer)?;
                let (ciphertext, shared_secret, ) = mlkem768::encapsulate(&key, buffer);
                Ok((shared_secret.as_slice().to_vec(), ciphertext.as_slice().to_vec()))
            }
        }
        
        fn extract_secret(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<SharedSecret, CryptoError> {
            let sk = mlkem768::MlKem768PrivateKey::try_from(private_key.bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
            let ct = mlkem768::MlKem768Ciphertext::try_from(ciphertext).map_err(|_| CryptoError::InvalidCiphertext)?;
            if !mlkem768::validate_private_key(&sk, &ct) {
                return Err(CryptoError::InvalidCiphertext);
            } else {
                let shared_secret = mlkem768::decapsulate(&sk, &ct);
                Ok(shared_secret.as_slice().to_vec())
            }
        }
        
    }
}

pub use mlkem::MLKEM768;
pub use sha256::SHA256;
pub use FNDSA512rs::FNDSA512;