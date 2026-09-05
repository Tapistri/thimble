mod identity;
mod internal;
#[cfg(test)]
mod tests {
    // use crate::internal::certificates::{
    //     Digest, DigestAlgorithm as DA, IdentityCertificate, KeyExchangeAlgorithm as KEA, Signature,
    //     SignatureAlgorithm, SigningKey, UTCTime, ValidityPeriod,
    // };
    // use crate::internal::crypto::{self, DigestAlgorithm, KeyExchangeAlgorithm};
    // use std::fs;

    #[test]
    fn some_test() {
        assert!(true);
    }

    #[test]
    fn create_identity() {
        // let keys = crypto::FNDSA512::new_keypair()
        //     .ok()
        //     .expect("failed to generate keypair");
        // let public_key_fingerprint = crypto::SHA256::digest(keys.get_public_key_bytes());
        // let signing_key = SigningKey {
        //     public_key: keys.get_public_key_bytes().into(),
        //     public_key_algorithm: SignatureAlgorithm::FnDsa512Draft,
        //     public_key_fingerprint: Digest {
        //         algorithm: DA::Sha256,
        //         digest: public_key_fingerprint.into(),
        //     },
        // };
        // let tbs_bytes = rasn::der::encode(&signing_key).unwrap();
        // let signature = crypto::FNDSA512::sign(&tbs_bytes, &keys.get_private_key_bytes())
        //     .ok()
        //     .expect("failed to sign");
        // let identity_certificate = IdentityCertificate {
        //     tbs_identity: signing_key,
        //     signature: Signature {
        //         algorithm: SignatureAlgorithm::FnDsa512Draft,
        //         signature: signature.into(),
        //     },
        // };
        // let encoded = rasn::der::encode(&identity_certificate).unwrap();

        // let decoded: IdentityCertificate = rasn::der::decode(&encoded).unwrap();

        // let tbs_bytes2 = rasn::der::encode(&decoded.tbs_identity).unwrap();
        // let signature2 = decoded.signature.signature;
        // let verified =
        //     crypto::FNDSA512::verify(&tbs_bytes2, &signature2, &decoded.tbs_identity.public_key);
        // assert!(verified, "signature verification failed");

        // fs::write("inspect/identity.tidc", encoded).unwrap();

        // let json = rasn::jer::encode(&identity_certificate).unwrap();
        // fs::write("inspect/identity.json", json).unwrap();

        // let uper = rasn::uper::encode(&identity_certificate).unwrap();
        // fs::write("inspect/identity.uper", uper).unwrap();
    }
}
