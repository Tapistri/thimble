use crate::internal::crypto::DigestAlgorithm;

mod sha256 {
    use sha2::{Digest, Sha256};

    pub fn digest(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

mod blake3 {
    use blake3;

    pub fn digest(data: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output = [0u8; 256 / 8];
        hasher.finalize_xof().fill(&mut output);
        output.to_vec()
    }
}

pub fn digest(data: &[u8], algorithm: DigestAlgorithm) -> Option<Vec<u8>> {
    match algorithm {
        DigestAlgorithm::Sha256 => Some(sha256::digest(data)),
        DigestAlgorithm::Blake3_256 => Some(blake3::digest(data)),
        #[allow(unused)]
        _ => None,
    }
}
