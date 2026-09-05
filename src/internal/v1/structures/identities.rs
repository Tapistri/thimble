use crate::internal::v1::structures::crypto::Digest;
use crate::internal::v1::structures::crypto::Signature;
use crate::internal::v1::structures::crypto::SigningKey;
use crate::internal::v1::structures::primatives::UTCTime;
use crate::internal::v1::structures::primatives::ValidityPeriod;

use rasn::AsnType;
use rasn::prelude::*;

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct InstanceAttestationRecord {
    pub identity_fingerprint: Digest,
    pub instance_fingerprint: Digest,
    pub id_proxy_fingerprint: Digest,
    pub id_validity_period: ValidityPeriod,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct IdentityCertificate {
    pub tbs_identity: SigningKey,
    pub signature: Signature,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct InstanceAttestationCertificate {
    pub record: InstanceAttestationRecord,
    pub signature: Signature,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRecord {
    pub publickey: SigningKey,
    pub serial_number: Integer,
    pub validity_period: ValidityPeriod,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyCertificate {
    pub record: HistoricalKeyRecord,
    pub signature: Signature,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRevocationRecord {
    pub revoked_key_fingerprint: Digest,
    pub revoked_key_serial_number: Integer,
    pub serial_number: Integer,
    pub revocation_time: UTCTime,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRevocationCertificate {
    pub record: HistoricalKeyRevocationRecord,
    pub signature: Signature,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct KeychainIdentifer {
    #[rasn(identifier = "clientIdentity")]
    pub client_identity: IdentityCertificate,
    #[rasn(identifier = "instanceIdentity")]
    pub instance_identity: Digest,
    #[rasn(identifier = "homeserverIdentity")]
    pub homeserver_identity: Digest,
    #[rasn(identifier = "recordCreationTime")]
    pub record_creation_time: UTCTime,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(choice, automatic_tags)]
pub enum HistoricalKeychainRecords {
    #[rasn(identifier = "historicalKey")]
    KeyRecord(HistoricalKeyRecord),
    #[rasn(identifier = "revocationRecord")]
    RevocationRecord(HistoricalKeyRevocationRecord),
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct IdentitiyKeychainCertificate {
    #[rasn(identifier = "tbskeychainIdentifer")]
    pub tbs_keychain_identifier: KeychainIdentifer,
    #[rasn(identifier = "clientIdentitySignature")]
    pub client_signature: Signature,
    #[rasn(identifier = "instanceSignature")]
    pub instance_signature: Signature,
    pub history: SequenceOf<HistoricalKeychainRecords>,
}
