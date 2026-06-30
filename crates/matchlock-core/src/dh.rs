use rand_core::{OsRng, RngCore};
use sha2::{Sha256, Digest};
use zeroize::Zeroizing;
use crate::types::{PrivateKey, PublicKey, MatchToken};

const MATCH_DOMAIN: &[u8] = b"matchlock-match-v1";

// X25519 Basepoint: Montgomery u-coordinate 9
pub(crate) const BASEPOINT: [u8; 32] = [
     9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(priv_bytes.as_mut());
    let pub_bytes = x25519_dalek::x25519(*priv_bytes, BASEPOINT);
    (PublicKey(pub_bytes), PrivateKey(*priv_bytes))
}

pub fn derive_match_token(my_priv: &PrivateKey, their_pub: &PublicKey, pool_id: &str) -> MatchToken {
    let shared = Zeroizing::new(x25519_dalek::x25519(my_priv.0, their_pub.0));
    let mut hasher = Sha256::new();
    hasher.update(shared.as_ref());
    hasher.update(pool_id.as_bytes());
    hasher.update(MATCH_DOMAIN);
    MatchToken(hasher.finalize().into())
}

pub fn derive_match_tokens(my_priv: &PrivateKey, their_pubs: &[PublicKey], pool_id: &str) -> Vec<MatchToken> {
    their_pubs.iter().map(|pk| derive_match_token(my_priv, pk, pool_id)).collect()
}
