use std::fmt;

#[derive(Debug)]
pub enum Error {
    InvalidKey(String),
    InvalidToken(String),
    DecryptionFailed,
    Serialization(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            Error::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Error::DecryptionFailed => write!(f, "decryption failed: authentication tag mismatch"),
            Error::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
