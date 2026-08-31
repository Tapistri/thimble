use rasn::AsnType;
use rasn::prelude::*;

#[derive(AsnType, Decode, Encode)]
#[rasn(value("0..18446744073709551615"))]
pub struct UTCTime(pub Integer);

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    FnDsa512Draft
}

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    Sha256
}

#[derive(AsnType, Decode, Encode, Copy, Clone, PartialEq, Debug)]
#[rasn(enumerated, automatic_tags)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    MlKem768
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct ValidityPeriod {
    pub not_before: UTCTime,
    pub not_after: UTCTime
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct Signature {
    pub algorithm: SignatureAlgorithm,
    pub signature: OctetString
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct Digest {
    pub algorithm: DigestAlgorithm,
    pub digest: OctetString
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct InstanceAttestationRecord {
    pub identity_fingerprint: Digest,
    pub instance_fingerprint: Digest,
    pub id_proxy_fingerprint: Digest,
    pub id_validity_period: ValidityPeriod
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct SigningKey {
    pub public_key: OctetString,
    pub public_key_algorithm: SignatureAlgorithm,
    pub public_key_fingerprint: Digest
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct IdentityCertificate {
    pub tbs_identity: SigningKey,
    pub signature: Signature
}


#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct InstanceAttestationCertificate {
    pub record: InstanceAttestationRecord,
    pub signature: Signature
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRecord {
    pub publickey: SigningKey,
    pub serial_number: Integer,
    pub validity_period: ValidityPeriod
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyCertificate {
    pub record: HistoricalKeyRecord,
    pub signature: Signature
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRevocationRecord {
    pub revoked_key_fingerprint: Digest,
    pub revoked_key_serial_number: Integer,
    pub serial_number: Integer,
    pub revocation_time: UTCTime
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeyRevocationCertificate {
    pub record: HistoricalKeyRevocationRecord,
    pub signature: Signature
}


#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct KeychainIdentifer {
    pub instance_identity_fingerprint: Digest,
    pub client_identity_fingerprint: Digest,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(choice, automatic_tags)]
pub enum HistoricalKeychainRecords {
    KeyRecord(HistoricalKeyRecord),
    RevocationRecord(HistoricalKeyRevocationRecord)
}

#[derive(AsnType, Decode, Encode)]
#[rasn(automatic_tags)]
pub struct HistoricalKeychainCertificate {
    pub tbs_keychain_identifier: KeychainIdentifer,
    pub client_signature: Signature,
    pub instance_signature: Signature,

    pub client_identity: IdentityCertificate,

    pub history: SequenceOf<HistoricalKeychainRecords>
}