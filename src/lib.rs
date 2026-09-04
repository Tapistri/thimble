mod internal;
mod identity;
#[cfg(test)]
mod tests {
    use std::fs;
    use crate::internal::crypto::{self, KeyExchangeAlgorithm, SigningAlgorithm, DigestAlgorithm};
    use crate::internal::certificates::{UTCTime, ValidityPeriod, Signature, Digest, IdentityCertificate, SigningKey, SignatureAlgorithm, DigestAlgorithm as DA, KeyExchangeAlgorithm as KEA};
    
    #[test]
    fn some_test() {
        assert!(true);
    }

    #[test]
    fn create_identity() {
        let keys = crypto::FNDSA512::new_keypair().ok().expect("failed to generate keypair");
        let public_key_fingerprint = crypto::SHA256::digest(keys.get_public_key_bytes());
        let signingKey = SigningKey {
            public_key: keys.get_public_key_bytes().into(),
            public_key_algorithm: SignatureAlgorithm::FnDsa512Draft,
            public_key_fingerprint: Digest {
                algorithm: DA::Sha256,
                digest: public_key_fingerprint.into()
            }
        };
        let tbsBytes = rasn::der::encode(&signingKey).unwrap();
        let signature = crypto::FNDSA512::sign(&tbsBytes, &keys.get_private_key_bytes()).ok().expect("failed to sign");
        let identityCertificate = IdentityCertificate {
            tbs_identity: signingKey,
            signature: Signature {
                algorithm: SignatureAlgorithm::FnDsa512Draft,
                signature: signature.into()
            }
        };
        let encoded = rasn::der::encode(&identityCertificate).unwrap();

        let decoded: IdentityCertificate = rasn::der::decode(&encoded).unwrap();

        let tbsBytes2 = rasn::der::encode(&decoded.tbs_identity).unwrap();
        let signature2 = decoded.signature.signature;
        let verified = crypto::FNDSA512::verify(&tbsBytes2, &signature2, &decoded.tbs_identity.public_key);
        assert!(verified, "signature verification failed");

        fs::write("inspect/identity.tidc", encoded).unwrap();

        let json = rasn::jer::encode(&identityCertificate).unwrap();
        fs::write("inspect/identity.json", json).unwrap();

        let uper = rasn::uper::encode(&identityCertificate).unwrap();
        fs::write("inspect/identity.uper", uper).unwrap();


    }
}