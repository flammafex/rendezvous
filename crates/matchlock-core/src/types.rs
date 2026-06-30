use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{Error, Result};

/// X25519 public key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) [u8; 32]);

/// X25519 private key (32 bytes) — zeroized on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub(crate) [u8; 32]);

/// Match token — SHA-256 of DH shared secret (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct MatchToken(pub(crate) [u8; 32]);

/// Commitment hash — SHA-256 of a MatchToken (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct CommitHash(pub(crate) [u8; 32]);

/// Nullifier — SHA-256 of private key + pool ID + domain (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Nullifier(pub(crate) [u8; 32]);

/// Ed25519 signing public key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct SigningPublicKey(pub(crate) [u8; 32]);

/// Ed25519 signing private key (32 bytes) — zeroized on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningPrivateKey(pub(crate) [u8; 32]);

/// Ed25519 signature (64 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub(crate) [u8; 64]);

// --- Debug impls: redact key material ---

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}
impl std::fmt::Debug for MatchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MatchToken({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommitHash({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nullifier({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningPublicKey({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for SigningPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningPrivateKey([REDACTED])")
    }
}
impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

// --- from_hex / to_hex for 32-byte types ---

macro_rules! impl_hex_32 {
    ($t:ident, $err_variant:ident, $label:literal) => {
        impl $t {
            pub fn from_hex(s: &str) -> Result<Self> {
                let bytes = hex::decode(s)
                    .map_err(|_| Error::$err_variant(format!("{}: expected 64-char hex", $label)))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| Error::$err_variant(format!("{}: must be 32 bytes", $label)))?;
                Ok(Self(arr))
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }
    };
}

impl_hex_32!(PublicKey,       InvalidKey,   "public key");
impl_hex_32!(PrivateKey,      InvalidKey,   "private key");
impl_hex_32!(MatchToken,      InvalidToken, "match token");
impl_hex_32!(CommitHash,      InvalidToken, "commit hash");
impl_hex_32!(Nullifier,       InvalidToken, "nullifier");
impl_hex_32!(SigningPublicKey, InvalidKey,   "signing public key");
impl_hex_32!(SigningPrivateKey,InvalidKey,   "signing private key");

impl Signature {
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|_| Error::InvalidKey("signature: expected 128-char hex".to_string()))?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("signature: must be 64 bytes".to_string()))?;
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
