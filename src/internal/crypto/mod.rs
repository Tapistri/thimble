pub mod digests;
pub mod kem;
pub mod keys;
pub mod random;
#[allow(unused)]
#[allow(dead_code)]
pub mod signing;
pub mod symmetric;
use std::{ops::Deref, ops::DerefMut, sync::LazyLock};

use rasn::{AsnType, Decode, Encode};

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug, Eq, Hash)]
#[rasn(enumerated, automatic_tags)]
#[repr(u8)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    #[rasn(identifier = "kx-ML-KEM-768")]
    MlKem768,
}
const KEY_EXCHANGE_ALGORITHM_MAX: u8 = KeyExchangeAlgorithm::MlKem768 as u8;

impl TryFrom<u8> for KeyExchangeAlgorithm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > KEY_EXCHANGE_ALGORITHM_MAX {
            return Err(());
        }
        // SAFETY: `value` is checked to be within `KEY_EXCHANGE_ALGORITHM_MAX` before this call.
        Ok(unsafe { std::mem::transmute::<u8, Self>(value) })
    }
}

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug, Eq, Hash)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
#[repr(u8)]
pub enum SymmetricEncryptionAlgorithm {
    #[rasn(identifier = "se-AES-256-GCM")]
    AES256Gcm,
    #[rasn(identifier = "se-AES-256-GCM-SIV")]
    AES256GcmSiv,
}

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug, Eq, Hash)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
#[repr(u8)]
pub enum SignatureAlgorithm {
    #[rasn(identifier = "sa-FN-DSA-512-draft")]
    FnDsa512Draft,
}
const SIGNATURE_ALGORITHM_MAX: u8 = SignatureAlgorithm::FnDsa512Draft as u8;

impl TryFrom<u8> for SignatureAlgorithm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > SIGNATURE_ALGORITHM_MAX {
            return Err(());
        }
        // SAFETY: `value` is checked to be within `SIGNATURE_ALGORITHM_MAX` before this call.
        Ok(unsafe { std::mem::transmute::<u8, Self>(value) })
    }
}

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug, Eq, Hash)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
#[repr(u8)]
pub enum DigestAlgorithm {
    #[rasn(identifier = "da-SHA-256")]
    Sha256,
    #[rasn(identifier = "da-BLAKE3-256")]
    Blake3_256,
}
const DIGEST_ALGORITHM_MAX: u8 = DigestAlgorithm::Blake3_256 as u8;

impl TryFrom<u8> for DigestAlgorithm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > DIGEST_ALGORITHM_MAX {
            return Err(());
        }
        // SAFETY: `value` is checked to be within `DIGEST_ALGORITHM_MAX` before this call.
        Ok(unsafe { std::mem::transmute::<u8, Self>(value) })
    }
}

const KEY_SIZE: usize = size_of::<u128>();
static XOR_KEY: LazyLock<u128> = LazyLock::new(|| rand::random::<u128>());
#[derive(Debug)]
pub struct PrivateBytes {
    bytes: ZeroedDropBytes,
}

impl PrivateBytes {
    pub fn new(bytes: &mut [u8]) -> PrivateBytes {
        let mut v = PrivateBytes {
            bytes: ZeroedDropBytes(vec![]),
        };
        v.set_bytes(bytes);
        v
    }

    pub fn get_bytes(&self) -> ZeroedDropBytes {
        let mut plain: ZeroedDropBytes = ZeroedDropBytes::new();
        let (chunks, remander) = self.bytes.as_chunks::<KEY_SIZE>();
        for chunk in chunks {
            let v = (u128::from_ne_bytes(*chunk) ^ *XOR_KEY).to_ne_bytes();
            plain.extend_from_slice(&v);
        }
        for (a, b) in remander.iter().zip(XOR_KEY.to_ne_bytes()) {
            plain.push(a ^ b)
        }
        plain
    }

    pub fn set_bytes(&mut self, bytes: &mut [u8]) {
        self.bytes.fill(0);
        self.bytes.clear();
        let (chunks, remander) = bytes.as_chunks::<KEY_SIZE>();
        for chunk in chunks {
            let v = (u128::from_ne_bytes(*chunk) ^ *XOR_KEY).to_ne_bytes();
            self.bytes.extend_from_slice(&v);
        }
        for (a, b) in remander.iter().zip(XOR_KEY.to_ne_bytes()) {
            self.bytes.push(a ^ b)
        }
    }
}

#[derive(Debug)]
pub struct ZeroedDropBytes(Vec<u8>);

impl ZeroedDropBytes {
    fn new() -> ZeroedDropBytes {
        ZeroedDropBytes(vec![])
    }
}

impl Drop for ZeroedDropBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl DerefMut for ZeroedDropBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for ZeroedDropBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// key -> ()

pub enum CryptoError {
    Unsupported,       // Operation is unsupported by the algorithm
    InvalidCiphertext, // Given ciphertext is invalid or corrupted
    InvalidKey,        // Key is in an invalid format or corrupted
    SystemError,       // Some other system error occurred (e.g. RNG failure)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyType {
    MLKEM768,
    FNDSA512,
}

type SharedSecret = Vec<u8>;
type Ciphertext = Vec<u8>;

// pub trait KeyExchangeAlgorithm {
// (public, private)
// fn new_keypair() -> Result<Keypair, CryptoError>;

// fn supports_mutual_secrets() -> bool;

// fn get_shared_key_size() -> usize;
// // public_key -> (shared_secret, ciphertext)
// fn derive_secret(public_key: &PublicKey) -> Result<(SharedSecret, Ciphertext), CryptoError>;
// fn derive_mutual_secrets(
//     public_key: &[&PublicKey],
// ) -> Result<(SharedSecret, Ciphertext), CryptoError>;

// fn extract_secret(private_key: &PrivateKey, ciphertext: &[u8])
// -> Result<SharedSecret, CryptoError>;
// }

// pub trait DigestAlgorithm {
//     fn digest(data: &[u8]) -> Vec<u8> {
//         todo!()
//     }
// }

// mod sha256 {
//     use crate::internal::crypto::DigestAlgorithm;
//     use sha2::{Digest, Sha256};

//     pub struct SHA256 {}

//     impl DigestAlgorithm for SHA256 {
//         fn digest(data: &[u8]) -> Vec<u8> {
//             let mut hasher = Sha256::new();
//             hasher.update(data);
//             hasher.finalize().to_vec()
//         }
//     }
// }

// mod mlkem {
//     pub struct MLKEM768 {}
//     use crate::internal::crypto::*;
//     use libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;
//     use libcrux_ml_kem::{mlkem768::MlKem768PublicKey, *};
//     use rand::{SeedableRng, TryRng};

//     fn random_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
//         let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)
//             .map_err(|e| CryptoError::SystemError)?;
//         rng.try_fill_bytes(buffer)
//             .map_err(|e| CryptoError::SystemError)?;
//         Ok(())
//     }

//     impl MLKEM768 {}

//     impl KeyExchangeAlgorithm for MLKEM768 {
//         fn derive_mutual_secrets(
//             _public_key: &[&PublicKey],
//         ) -> Result<(SharedSecret, Ciphertext), CryptoError> {
//             Err(CryptoError::Unsupported)
//         }

//         fn new_keypair() -> Result<Keypair, CryptoError> {
//             let mut seed = [0u8; KEY_GENERATION_SEED_SIZE];
//             random_bytes(&mut seed)?;
//             let keypair = mlkem::mlkem768::generate_key_pair(seed);
//             let private_key = keypair.sk().to_vec();
//             let pub_key = keypair.pk().to_vec();
//             Ok(Keypair::new(&private_key, &pub_key, KeyType::MLKEM768))
//         }

//         fn supports_mutual_secrets() -> bool {
//             false
//         }

//         fn get_shared_key_size() -> usize {
//             mlkem::SHARED_SECRET_SIZE
//         }

//         fn derive_secret(
//             public_key: &PublicKey,
//         ) -> Result<(SharedSecret, Ciphertext), CryptoError> {
//             let key = MlKem768PublicKey::try_from(public_key.bytes.as_slice())
//                 .map_err(|_| CryptoError::InvalidKey)?;
//             if !mlkem768::validate_public_key(&key) {
//                 return Err(CryptoError::InvalidKey);
//             } else {
//                 let mut buffer = [0u8; mlkem::SHARED_SECRET_SIZE];
//                 random_bytes(&mut buffer)?;
//                 let (ciphertext, shared_secret) = mlkem768::encapsulate(&key, buffer);
//                 Ok((
//                     shared_secret.as_slice().to_vec(),
//                     ciphertext.as_slice().to_vec(),
//                 ))
//             }
//         }

//         fn extract_secret(
//             private_key: &PrivateKey,
//             ciphertext: &[u8],
//         ) -> Result<SharedSecret, CryptoError> {
//             let sk = mlkem768::MlKem768PrivateKey::try_from(private_key.bytes.as_slice())
//                 .map_err(|_| CryptoError::InvalidKey)?;
//             let ct = mlkem768::MlKem768Ciphertext::try_from(ciphertext)
//                 .map_err(|_| CryptoError::InvalidCiphertext)?;
//             if !mlkem768::validate_private_key(&sk, &ct) {
//                 return Err(CryptoError::InvalidCiphertext);
//             } else {
//                 let shared_secret = mlkem768::decapsulate(&sk, &ct);
//                 Ok(shared_secret.as_slice().to_vec())
//             }
//         }
//     }
// }

// pub use fndsa512rs::FNDSA512;
// pub use mlkem::MLKEM768;
// pub use sha256::SHA256;
