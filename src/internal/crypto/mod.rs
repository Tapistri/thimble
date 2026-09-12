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
