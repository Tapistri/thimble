use crate::internal::{
    crypto::signing::VerifyKey,
    v1::structures::identities::{
        HistoricalKeychainRecords, IdentitiyKeychainCertificate, IdentityCertificate,
    },
};

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
        let b = Box::new(());
        todo!()
    }
}

pub struct IdentityChain {
    raw: IdentitiyKeychainCertificate,
}

impl IdentityChain {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let identity_chain: IdentitiyKeychainCertificate =
            rasn::der::decode(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self {
            raw: identity_chain,
        })
    }

    pub fn get_latest_key(&self) -> Result<Box<dyn VerifyKey>, IdentityError> {
        let highest_sn = self.raw.history.iter().fold(
            Ok(0),
            |acc: Result<i32, IdentityError>, entry| -> Result<i32, IdentityError> {
                match acc {
                    Ok(acc) => Ok(acc.max(match entry {
                        HistoricalKeychainRecords::KeyRecord(rec) => rec
                            .serial_number
                            .clone()
                            .try_into()
                            .map_err(|_| IdentityError::InvalidEncoding)?,
                        HistoricalKeychainRecords::RevocationRecord(rev) => rev
                            .serial_number
                            .clone()
                            .try_into()
                            .map_err(|_| IdentityError::InvalidEncoding)?,
                    })),
                    Err(err) => Err(err),
                }
            },
        );
        if let Ok(highest_sn) = highest_sn {
            todo!()
        } else {
            Err(IdentityError::InvalidEncoding)
        }
    }
}
