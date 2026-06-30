use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use crate::error::{Error, Result};
use crate::types::{PrivateKey, PublicKey};

const ENCRYPTION_DOMAIN: &[u8] = b"matchlock-encrypt-v1";

pub struct EncryptedBox {
    pub ephemeral_public_key: PublicKey,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

// Mirrors the TypeScript JSON shape exactly (camelCase field names)
#[derive(Serialize, Deserialize)]
struct EncryptedBoxJson {
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(shared: &[u8; 32], nonce: &[u8; 24]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(ENCRYPTION_DOMAIN, key.as_mut()).expect("HKDF expand failed: 32 bytes always fits");
    key
}

pub fn encrypt_for_public_key(plaintext: &[u8], recipient: &PublicKey) -> EncryptedBox {
    // Generate ephemeral keypair
    let mut eph_priv = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(eph_priv.as_mut());
    let eph_pub = x25519_dalek::x25519(*eph_priv, crate::dh::BASEPOINT);

    // X25519 DH
    let shared = Zeroizing::new(x25519_dalek::x25519(*eph_priv, recipient.0));

    // Random nonce
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // HKDF-SHA256(ikm=shared, salt=nonce, info=ENCRYPTION_DOMAIN)
    let key = derive_key(&shared, &nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key is 32 bytes");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("XChaCha20Poly1305 encryption failed");

    EncryptedBox { ephemeral_public_key: PublicKey(eph_pub), nonce, ciphertext }
}

pub fn decrypt_with_private_key(box_: &EncryptedBox, priv_key: &PrivateKey) -> Result<Vec<u8>> {
    let shared = Zeroizing::new(x25519_dalek::x25519(priv_key.0, box_.ephemeral_public_key.0));
    let key = derive_key(&shared, &box_.nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key is 32 bytes");
    cipher
        .decrypt(XNonce::from_slice(&box_.nonce), box_.ciphertext.as_slice())
        .map_err(|_| Error::DecryptionFailed)
}

pub fn serialize_encrypted_box(box_: &EncryptedBox) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let json = serde_json::to_string(&EncryptedBoxJson {
        ephemeral_public_key: hex::encode(box_.ephemeral_public_key.0),
        nonce: hex::encode(box_.nonce),
        ciphertext: hex::encode(&box_.ciphertext),
    })
    .expect("JSON serialization failed");
    STANDARD.encode(json.as_bytes())
}

pub fn deserialize_encrypted_box(s: &str) -> Result<EncryptedBox> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let json_bytes = STANDARD
        .decode(s)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    let json_str = std::str::from_utf8(&json_bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    let j: EncryptedBoxJson = serde_json::from_str(json_str)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    let epk: [u8; 32] = hex::decode(&j.ephemeral_public_key)
        .map_err(|_| Error::InvalidKey("invalid ephemeral public key hex".to_string()))?
        .try_into()
        .map_err(|_| Error::InvalidKey("ephemeral public key must be 32 bytes".to_string()))?;
    let nonce: [u8; 24] = hex::decode(&j.nonce)
        .map_err(|_| Error::Serialization("invalid nonce hex".to_string()))?
        .try_into()
        .map_err(|_| Error::Serialization("nonce must be 24 bytes".to_string()))?;
    let ciphertext = hex::decode(&j.ciphertext)
        .map_err(|_| Error::Serialization("invalid ciphertext hex".to_string()))?;

    Ok(EncryptedBox { ephemeral_public_key: PublicKey(epk), nonce, ciphertext })
}
