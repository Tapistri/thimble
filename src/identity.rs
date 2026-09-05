use crate::internal::certificates::{IdentitiyKeychainCertificate, IdentityCertificate};

pub enum IdentityError {
    InvalidEncoding,
}

pub struct Identity {
    raw: IdentityCertificate,
}

impl Identity {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let identity_certificate: IdentityCertificate =
            rasn::der::decode(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self {
            raw: identity_certificate,
        })
    }

    pub fn verify(&self) -> Result<bool, IdentityError> {
        todo!()
    }
}

pub struct IdentityChain {
    raw: IdentitiyKeychainCertificate,
}

impl IdentityChain {
    /**
     * Needed information for validation:
     *  Instance's IKC
     *  ClientIdentityPubkey
     */
    pub fn validate(&self) -> Result<(), IdentityError> {
        todo!()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let identity_chain: IdentitiyKeychainCertificate =
            rasn::der::decode(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self {
            raw: identity_chain,
        })
    }
}
