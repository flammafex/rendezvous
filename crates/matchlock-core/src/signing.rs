use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{SigningPrivateKey, SigningPublicKey, Signature};

const SIGNING_DOMAIN: &[u8] = b"matchlock-sign-v1";

pub struct SignedRequest {
    pub signature: Signature,
    pub timestamp_ms: u64,
}

pub fn signing_public_key_from_private(priv_key: &SigningPrivateKey) -> SigningPublicKey {
    SigningPublicKey(SigningKey::from_bytes(&priv_key.0).verifying_key().to_bytes())
}

pub fn generate_signing_keypair() -> (SigningPublicKey, SigningPrivateKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        SigningPublicKey(verifying_key.to_bytes()),
        SigningPrivateKey(signing_key.to_bytes()),
    )
}

fn prehash(message: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SIGNING_DOMAIN);
    h.update(message.as_bytes());
    h.finalize().into()
}

pub fn sign(message: &str, priv_key: &SigningPrivateKey) -> Signature {
    let signing_key = SigningKey::from_bytes(&priv_key.0);
    let hash = prehash(message);
    Signature(signing_key.sign(&hash).to_bytes())
}

pub fn verify(message: &str, sig: &Signature, pub_key: &SigningPublicKey) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_key.0) else { return false; };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&sig.0) else { return false; };
    let hash = prehash(message);
    verifying_key.verify(&hash, &signature).is_ok()
}

pub fn create_signed_request(action: &str, pool_id: &str, priv_key: &SigningPrivateKey) -> SignedRequest {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64;
    let message = format!("{action}:{pool_id}:{timestamp_ms}");
    SignedRequest { signature: sign(&message, priv_key), timestamp_ms }
}

pub fn verify_signed_request(
    action: &str,
    pool_id: &str,
    sig: &Signature,
    timestamp_ms: u64,
    pub_key: &SigningPublicKey,
    max_age_ms: u64,
) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64;
    if now_ms.abs_diff(timestamp_ms) > max_age_ms {
        return false;
    }
    let message = format!("{action}:{pool_id}:{timestamp_ms}");
    verify(&message, sig, pub_key)
}
