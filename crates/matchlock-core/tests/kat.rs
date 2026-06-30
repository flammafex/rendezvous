//! Known-answer tests — vectors must match the TypeScript implementation exactly.
//!
//! RFC 7748 §6.1 X25519 test vectors used for key inputs.
//! Expected outputs computed by the TypeScript matchlock library.

use matchlock_core::{
    commit::{commit_token, commit_tokens, verify_commitment},
    dh::{derive_match_token, derive_match_tokens, generate_keypair},
    ecies::{decrypt_with_private_key, deserialize_encrypted_box, encrypt_for_public_key, serialize_encrypted_box},
    nullifier::derive_nullifier,
    signing::{
        create_signed_request, generate_signing_keypair, sign,
        signing_public_key_from_private, verify, verify_signed_request,
    },
    types::{MatchToken, PrivateKey, PublicKey},
};

// RFC 7748 §6.1 keys
const ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d";
const BOB_PUB: &str    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const BOB_PRIV: &str   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const ALICE_PUB: &str  = "50c38b5838a8bb38714b04f1f9af579782b8a1d6803f95aab49c3266c3543c3e";

// --- derive_match_token KAT ---

#[test]
fn kat_match_token_alice_to_bob() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let token = derive_match_token(&alice_priv, &bob_pub, "test-pool");
    assert_eq!(
        token.to_hex(),
        "bbfee0cd9a72d348a1a4dafee9ad8c055f02c79e0d341ff4aa425583030492bf",
        "token KAT mismatch"
    );
}

#[test]
fn kat_match_token_commutativity() {
    // DH is commutative: derive_match_token(alice, bob) == derive_match_token(bob, alice)
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let bob_priv   = PrivateKey::from_hex(BOB_PRIV).unwrap();
    let alice_pub  = PublicKey::from_hex(ALICE_PUB).unwrap();

    let alice_token = derive_match_token(&alice_priv, &bob_pub, "test-pool");
    let bob_token   = derive_match_token(&bob_priv, &alice_pub, "test-pool");
    assert_eq!(alice_token, bob_token, "DH commutativity violated");
}

#[test]
fn kat_match_token_pool_scoped() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let t1 = derive_match_token(&alice_priv, &bob_pub, "pool-a");
    let t2 = derive_match_token(&alice_priv, &bob_pub, "pool-b");
    assert_ne!(t1, t2, "tokens must be pool-scoped");
}

// --- commit_token KAT ---

#[test]
fn kat_commit_token_zero_bytes() {
    let zero_token = MatchToken::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let hash = commit_token(&zero_token);
    assert_eq!(
        hash.to_hex(),
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        "commit_token KAT mismatch"
    );
}

#[test]
fn commit_tokens_batch_matches_individual() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let token = derive_match_token(&alice_priv, &bob_pub, "pool-1");

    let singles = [commit_token(&token)];
    let batch   = commit_tokens(&[token]);
    assert_eq!(singles[0], batch[0]);
}

#[test]
fn verify_commitment_roundtrip() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let token = derive_match_token(&alice_priv, &bob_pub, "pool-1");
    let hash  = commit_token(&token);
    assert!(verify_commitment(&token, &hash));
}

#[test]
fn verify_commitment_rejects_wrong_token() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let bob_priv   = PrivateKey::from_hex(BOB_PRIV).unwrap();
    let alice_pub  = PublicKey::from_hex(ALICE_PUB).unwrap();

    let token_ab   = derive_match_token(&alice_priv, &bob_pub, "pool");
    let token_ba   = derive_match_token(&bob_priv, &alice_pub, "pool-2");
    let hash_ab    = commit_token(&token_ab);
    assert!(!verify_commitment(&token_ba, &hash_ab));
}

// --- derive_nullifier KAT ---

#[test]
fn kat_nullifier_alice() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let nullifier  = derive_nullifier(&alice_priv, "test-pool");
    assert_eq!(
        nullifier.to_hex(),
        "9728a87b7ef7fb92a1438c557b5621c0c2f7c67e1d9847e8f6e31dd6e8e05d0c",
        "nullifier KAT mismatch"
    );
}

#[test]
fn nullifier_is_pool_scoped() {
    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let n1 = derive_nullifier(&alice_priv, "pool-a");
    let n2 = derive_nullifier(&alice_priv, "pool-b");
    assert_ne!(n1, n2);
}

// --- generate_keypair ---

#[test]
fn generate_keypair_produces_valid_keys() {
    let (pub_key, priv_key) = generate_keypair();
    // Keys should be valid hex (round-trip)
    let pub2 = PublicKey::from_hex(&pub_key.to_hex()).unwrap();
    let _ = PrivateKey::from_hex(&priv_key.to_hex()).unwrap();
    assert_eq!(pub_key, pub2);
}

#[test]
fn generated_keypair_participates_in_dh() {
    let (pub_a, priv_a) = generate_keypair();
    let (pub_b, priv_b) = generate_keypair();
    let t_ab = derive_match_token(&priv_a, &pub_b, "pool");
    let t_ba = derive_match_token(&priv_b, &pub_a, "pool");
    assert_eq!(t_ab, t_ba, "DH commutativity violated for generated keys");
}

#[test]
fn derive_match_tokens_batch() {
    let (pub_b, _) = generate_keypair();
    let (pub_c, _) = generate_keypair();
    let (_, priv_a) = generate_keypair();
    let tokens = derive_match_tokens(&priv_a, &[pub_b, pub_c], "pool");
    assert_eq!(tokens.len(), 2);
}

// --- ECIES ---

#[test]
fn ecies_encrypt_decrypt_roundtrip() {
    let (pub_key, priv_key) = generate_keypair();
    let plaintext = b"hello matchlock";
    let box_ = encrypt_for_public_key(plaintext, &pub_key);
    let recovered = decrypt_with_private_key(&box_, &priv_key).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn ecies_decrypt_rejects_tampered_ciphertext() {
    let (pub_key, priv_key) = generate_keypair();
    let box_ = encrypt_for_public_key(b"secret", &pub_key);
    let mut tampered = box_.ciphertext.clone();
    tampered[0] ^= 0xff;
    let bad_box = matchlock_core::ecies::EncryptedBox {
        ephemeral_public_key: box_.ephemeral_public_key,
        nonce: box_.nonce,
        ciphertext: tampered,
    };
    assert!(decrypt_with_private_key(&bad_box, &priv_key).is_err());
}

#[test]
fn ecies_serialize_deserialize_roundtrip() {
    let (pub_key, priv_key) = generate_keypair();
    let box_ = encrypt_for_public_key(b"roundtrip", &pub_key);
    let serialized = serialize_encrypted_box(&box_);
    let box2 = deserialize_encrypted_box(&serialized).unwrap();
    let recovered = decrypt_with_private_key(&box2, &priv_key).unwrap();
    assert_eq!(recovered, b"roundtrip");
}

#[test]
fn ecies_serialized_format_is_base64_json() {
    // The serialized box must be valid base64 encoding a JSON object with
    // exactly the fields expected by the TypeScript implementation.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let (pub_key, _) = generate_keypair();
    let box_ = encrypt_for_public_key(b"test", &pub_key);
    let serialized = serialize_encrypted_box(&box_);
    let json_bytes = STANDARD.decode(&serialized).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
    assert!(json.get("ephemeralPublicKey").is_some());
    assert!(json.get("nonce").is_some());
    assert!(json.get("ciphertext").is_some());
}

// --- Signing ---

#[test]
fn signing_roundtrip() {
    let (_, priv_key) = generate_signing_keypair();
    let (pub_key, _)  = generate_signing_keypair();
    // Generate a fresh pair to actually test sign + verify together
    let (pub_key2, priv_key2) = generate_signing_keypair();
    let sig = sign("hello", &priv_key2);
    assert!(verify("hello", &sig, &pub_key2));
    // Different key should not verify
    assert!(!verify("hello", &sig, &pub_key));
    let _ = (priv_key, pub_key); // suppress unused warnings
}

#[test]
fn signing_wrong_message_fails() {
    let (pub_key, priv_key) = generate_signing_keypair();
    let sig = sign("correct message", &priv_key);
    assert!(!verify("wrong message", &sig, &pub_key));
}

#[test]
fn signed_request_verifies() {
    let (pub_key, priv_key) = generate_signing_keypair();
    let req = create_signed_request("psi-setup", "pool-123", &priv_key);
    assert!(verify_signed_request(
        "psi-setup",
        "pool-123",
        &req.signature,
        req.timestamp_ms,
        &pub_key,
        5 * 60 * 1000,
    ));
}

#[test]
fn signed_request_rejects_expired() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let (pub_key, priv_key) = generate_signing_keypair();
    // Construct a request with a timestamp 10 minutes in the past
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let old_timestamp_ms = now_ms - 10 * 60 * 1000;
    let message = format!("psi-setup:pool-123:{old_timestamp_ms}");
    let sig = sign(&message, &priv_key);
    // max_age_ms = 5 minutes → request is 10 minutes old → rejected
    assert!(!verify_signed_request(
        "psi-setup",
        "pool-123",
        &sig,
        old_timestamp_ms,
        &pub_key,
        5 * 60 * 1000,
    ));
}

#[test]
fn kat_signing_known_private_key() {
    // KAT private key from PROTOCOL.md
    let priv_key = matchlock_core::types::SigningPrivateKey::from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55",
    )
    .unwrap();
    let pub_key = signing_public_key_from_private(&priv_key);
    let sig = sign("test", &priv_key);
    assert!(verify("test", &sig, &pub_key));
}

// --- types: from_hex / to_hex roundtrips ---

#[test]
fn type_hex_roundtrips() {
    let (pub_key, _priv_key) = generate_keypair();
    assert_eq!(PublicKey::from_hex(&pub_key.to_hex()).unwrap(), pub_key);

    let alice_priv = PrivateKey::from_hex(ALICE_PRIV).unwrap();
    let bob_pub    = PublicKey::from_hex(BOB_PUB).unwrap();
    let token = derive_match_token(&alice_priv, &bob_pub, "pool");
    assert_eq!(MatchToken::from_hex(&token.to_hex()).unwrap(), token);
}

#[test]
fn type_from_hex_rejects_invalid() {
    assert!(PublicKey::from_hex("not-hex").is_err());
    assert!(PublicKey::from_hex("deadbeef").is_err()); // too short
    assert!(PrivateKey::from_hex("zz".repeat(32).as_str()).is_err());
    assert!(MatchToken::from_hex("").is_err());
}

