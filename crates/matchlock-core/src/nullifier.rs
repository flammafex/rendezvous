use sha2::{Sha256, Digest};
use zeroize::Zeroizing;
use crate::types::{PrivateKey, Nullifier};

const NULLIFIER_DOMAIN: &[u8] = b"matchlock-nullifier-v1";

pub fn derive_nullifier(priv_key: &PrivateKey, pool_id: &str) -> Nullifier {
    let key_bytes = Zeroizing::new(priv_key.0);
    let mut hasher = Sha256::new();
    hasher.update(key_bytes.as_ref());
    hasher.update(pool_id.as_bytes());
    hasher.update(NULLIFIER_DOMAIN);
    Nullifier(hasher.finalize().into())
}
