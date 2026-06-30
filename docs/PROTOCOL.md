# Matchlock Protocol Specification

## Overview

Matchlock is a protocol for mutual preference detection. Two parties can discover they mutually selected each other without either party or the server learning about unilateral (non-mutual) selections.

## Participants

- **Participant**: A user with an X25519 keypair. Derives match tokens locally.
- **Pool owner**: Holds the PSI server key (encrypted). Processes PSI queries.
- **Server**: Stores encrypted PSI setup and queues PSI requests. Learns nothing about preferences.

## Protocol

### Phase 1: Key generation

Each participant generates an X25519 keypair out-of-band:

```
(priv_i, pub_i) ← X25519.keygen()
```

Public keys are published to the pool.

**Security note:** The private key is used for both DH matching and nullifier derivation. It must never leave the client.

### Phase 2: Token derivation

For each participant j that participant i wants to select:

```
shared_ij = X25519(priv_i, pub_j)
token_ij  = SHA-256( shared_ij || utf8(pool_id) || utf8("matchlock-match-v1") )
```

By X25519 commutativity: `shared_ij == shared_ji`, therefore `token_ij == token_ji`.

A match token is identical for both parties iff both derived it — which requires both to have selected each other.

**Note on domain separator ordering:** The pool_id and domain constant are concatenated after the shared secret without a length prefix. This is safe because the domain constant is a compile-time fixed string, making collisions between `(pool_id, domain)` pairs unreachable in practice.

### Phase 3: Commitment (optional, prevents timing attacks)

```
commit_ij = SHA-256( raw_bytes(token_ij) )
```

The commitment is SHA-256 of the 32 raw bytes encoded by the token hex string, not of the hex string itself. Participants submit commitments first, then reveal tokens after a deadline.

### Phase 4: Nullifier generation

```
nullifier_i = SHA-256( priv_i_bytes || utf8(pool_id) || utf8("matchlock-nullifier-v1") )
```

Nullifiers prevent a participant from submitting multiple preference sets within a pool, while remaining unlinkable across pools.

### Phase 5: PSI setup (pool owner)

```
(psi_server_key, setup_msg) ← PSI.server_setup(all_tokens)
encrypted_key = ECIES_encrypt(psi_server_key, owner_pub)
```

`setup_msg` is public. `encrypted_key` is stored on the server but the server cannot decrypt it.

#### ECIES construction

```
eph_priv, eph_pub ← X25519.keygen()
shared    = X25519(eph_priv, recipient_pub)
nonce     ← random(24 bytes)
key       = HKDF-SHA-256( ikm=shared, salt=nonce, info=utf8("matchlock-encrypt-v1"), len=32 )
ciphertext = XChaCha20-Poly1305( key, nonce ).encrypt( plaintext )
```

**HKDF salt choice:** The nonce is used as the HKDF salt rather than an empty salt or a fixed constant. Because the nonce is uniformly random and fresh per encryption, this provides per-message key diversification at the HKDF layer as well as the cipher layer. Cross-implementers must use the same nonce value for both the HKDF salt and the XChaCha20-Poly1305 nonce.

### Phase 6: PSI query (participant)

```
(psi_request, client_session) ← PSI.client_request(my_tokens)
```

The server learns request size but not its contents. The client session bundles the client key and the input array; both are required for Phase 8 and must not be separated.

### Phase 7: PSI processing (pool owner)

```
psi_server_key = ECIES_decrypt(encrypted_key, owner_priv)
psi_response   = PSI.process_request(psi_server_key, psi_request)
```

### Phase 8: Intersection computation (participant)

```
match_indices = PSI.compute_intersection(client_session, setup_msg, psi_response)
matches = [my_tokens[i] for i in match_indices]
```

Only the querier learns the result.

**Important:** The tokens in `client_session` must be the same array in the same order as submitted in Phase 6. The PSI library replays the blinded request internally to restore OPRF state. Using the opaque session object (rather than a bare client key) prevents accidental mismatch.

## Cryptographic primitives

| Primitive | Algorithm | Domain separator | Notes |
|-----------|-----------|-----------------|-------|
| Key agreement | X25519 | — | @noble/curves |
| Token hashing | SHA-256 | `matchlock-match-v1` | @noble/hashes |
| Commitment | SHA-256 (of raw token bytes) | — | @noble/hashes |
| Nullifier | SHA-256 | `matchlock-nullifier-v1` | @noble/hashes |
| Asymmetric encryption | X25519 + HKDF-SHA-256 + XChaCha20-Poly1305 | `matchlock-encrypt-v1` | @noble/{curves,hashes,ciphers} |
| Signing | Ed25519 (pre-hashed with SHA-256) | `matchlock-sign-v1` | @noble/curves |
| PSI | ECDH-based PSI | — | @openmined/psi.js |

### Signing double-hash detail

The signing construction is:

```
msg_hash  = SHA-256( utf8("matchlock-sign-v1") || utf8(message) )
signature = Ed25519.sign( msg_hash, signing_priv )
```

This is Ed25519 over a pre-hashed message (effectively Ed25519ph with SHA-256 instead of the standard SHA-512). The SHA-256 layer provides domain separation; @noble/curves' `ed25519.sign` then applies its own internal SHA-512 to the pre-hash bytes. Cross-implementers must apply **both** layers: SHA-256 domain-separation first, then pass the 32-byte hash to a standard Ed25519 `sign` primitive.

## Security properties

**Unilateral privacy**: `T_ij = SHA-256(DH(priv_i, pub_j) || ...)` is computationally indistinguishable from random to anyone without `priv_i` or `priv_j`.

**Server opacity**: The server stores only opaque base64 PSI artifacts and cannot interpret them without the owner's private key.

**Owner-held key trust model**: The PSI server key is ECIES-encrypted to the pool owner's X25519 public key. A compromised server operator cannot process PSI queries retroactively.

**Pool isolation**: The `pool_id` domain separator ensures tokens from different pools are independent.

## Out of scope

- Sybil resistance (use Freebird for anonymous rate-limited authorization)
- Timestamping (use Witness for threshold timestamps)
- Transport security (use TLS)
- Metadata privacy (timing, IP, message sizes)

---

## Implementers' guide

This section provides exact byte sequences for verifying an independent implementation against the TypeScript reference. All values are lowercase hex. Domain separator strings are UTF-8 encoded with no null terminator or length prefix.

### Domain separator strings

| Operation | Domain string |
|-----------|---------------|
| Match token | `matchlock-match-v1` |
| Nullifier | `matchlock-nullifier-v1` |
| ECIES key derivation | `matchlock-encrypt-v1` |
| Signing | `matchlock-sign-v1` |

### Token derivation KAT

Test inputs use the RFC 7748 §6.1 X25519 scalar multiplication test vectors.

```
alice_priv (hex): 77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d
alice_pub  (hex): 50c38b5838a8bb38714b04f1f9af579782b8a1d6803f95aab49c3266c3543c3e
bob_priv   (hex): 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
bob_pub    (hex): de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
pool_id         : test-pool
shared_secret   : 1318f77350ce2907779f7904eab8faa0c0ff546e8dd55bb64dff7716d522b139

hash_input = shared_secret_bytes
           || utf8("test-pool")
           || utf8("matchlock-match-v1")

token (hex): bbfee0cd9a72d348a1a4dafee9ad8c055f02c79e0d341ff4aa425583030492bf
```

Verify commutativity: `deriveMatchToken(bob_priv, alice_pub, pool_id)` must produce the same token.

### Commitment KAT

```
token_bytes (hex): 0000000000000000000000000000000000000000000000000000000000000000
commit      (hex): 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
```

This is SHA-256 of 32 zero bytes.

### Nullifier KAT

```
priv_key (hex): 77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d
pool_id       : test-pool

hash_input = priv_key_bytes
           || utf8("test-pool")
           || utf8("matchlock-nullifier-v1")

nullifier (hex): 9728a87b7ef7fb92a1438c557b5621c0c2f7c67e1d9847e8f6e31dd6e8e05d0c
```

### Signing KAT

```
signing_priv (hex): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
signing_pub  (hex): 700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41
message            : psi-setup:test-pool:1700000000000

msg_hash = SHA-256( utf8("matchlock-sign-v1") || utf8(message) )
         = 734cf9b46e533c1af41f0ba38b76f7690dafc7f204b6ec30758d51f0dab7dfd5

signature (hex):
  5da3e36456cd5ad371048aa66d494832d5e5d28f34400c1a0d604e09a017c4e5
  2dde6c80c3326962420a5b7aa480bd6e4f0412aaae45170612165b8c4e149b01
```

Note: pass `msg_hash` (32 bytes) directly to Ed25519 `sign`/`verify`. Do **not** hash it again.

### ECIES KAT

```
recipient_pub  (hex): 50c38b5838a8bb38714b04f1f9af579782b8a1d6803f95aab49c3266c3543c3e
ephemeral_priv (hex): a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
ephemeral_pub  (hex): 605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c
shared_secret  (hex): 037220290b39b449fd4384f0315accc86374c4e703ebd2e11b5d363ae84bb727
nonce          (hex): 0102030405060708090a0b0c0d0e0f101112131415161718

HKDF-SHA-256( ikm=shared_secret, salt=nonce, info=utf8("matchlock-encrypt-v1"), len=32 )

plaintext  : hello matchlock  (UTF-8, 15 bytes)
ciphertext (hex, 31 bytes including 16-byte Poly1305 tag):
  24d506352e961e55a9aa61d671214e4bc66c28f36a7e396c87167d955976ea
```
