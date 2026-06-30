use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use crate::types::{MatchToken, CommitHash};

pub fn commit_token(token: &MatchToken) -> CommitHash {
    CommitHash(Sha256::digest(token.0).into())
}

pub fn commit_tokens(tokens: &[MatchToken]) -> Vec<CommitHash> {
    tokens.iter().map(commit_token).collect()
}

pub fn verify_commitment(token: &MatchToken, commit_hash: &CommitHash) -> bool {
    bool::from(commit_token(token).0.ct_eq(&commit_hash.0))
}
