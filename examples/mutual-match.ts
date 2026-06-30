/**
 * Matchlock — end-to-end mutual match example
 *
 * Shows the full DH + PSI flow:
 * 1. Alice and Bob each generate keypairs
 * 2. Alice selects Bob (and Carol); Bob selects Alice (and Dave)
 * 3. Both derive the same match token for their mutual selection
 * 4. Pool owner uses PSI to let Bob discover the match without
 *    learning Alice's non-matching selections
 */

import { generateKeypair, deriveMatchToken } from '../src/matchlock/dh/index.js';
import { commitToken } from '../src/matchlock/dh/commit.js';
import { deriveNullifier } from '../src/matchlock/dh/nullifier.js';
import { decryptWithPrivateKey, deserializeEncryptedBox } from '../src/matchlock/dh/ecies.js';
import { PsiService } from '../src/matchlock/psi/service.js';

async function main() {
  const poolId = 'example-pool';

  const alice = generateKeypair();
  const bob = generateKeypair();
  const carol = generateKeypair();
  const dave = generateKeypair();

  console.log('Alice public key:', alice.publicKey.slice(0, 16) + '...');
  console.log('Bob public key:  ', bob.publicKey.slice(0, 16) + '...');

  // Token derivation (client-side, no server involved)
  const aliceSelectsBob = deriveMatchToken(alice.privateKey, bob.publicKey, poolId);
  const aliceSelectsCarol = deriveMatchToken(alice.privateKey, carol.publicKey, poolId);
  const bobSelectsAlice = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);
  const bobSelectsDave = deriveMatchToken(bob.privateKey, dave.publicKey, poolId);

  console.log('\nDH mutual match:');
  console.log('Alice→Bob token:', aliceSelectsBob.slice(0, 16) + '...');
  console.log('Bob→Alice token:', bobSelectsAlice.slice(0, 16) + '...');
  console.log('Tokens equal?  ', aliceSelectsBob === bobSelectsAlice); // true

  // Commit phase
  const aliceCommit = commitToken(aliceSelectsBob);
  console.log('\nAlice commits:', aliceCommit.slice(0, 16) + '...');

  // Nullifier
  const aliceNullifier = deriveNullifier(alice.privateKey, poolId);
  console.log('Alice nullifier:', aliceNullifier.slice(0, 16) + '...');

  // PSI phase
  console.log('\nInitializing PSI (loads WASM)...');
  const psi = new PsiService();
  await psi.init();

  const ownerKeypair = generateKeypair();
  const allPoolTokens = [aliceSelectsBob, aliceSelectsCarol];
  const setup = await psi.createOwnerEncryptedSetup(
    { poolId, matchTokens: allPoolTokens },
    ownerKeypair.publicKey,
  );

  const { request, session } = await psi.createRequest([bobSelectsAlice, bobSelectsDave]);

  const serverKey = decryptWithPrivateKey(
    deserializeEncryptedBox(setup.encryptedServerKey),
    ownerKeypair.privateKey,
  );
  const response = await psi.processRequestWithDecryptedKey(serverKey, request);

  const result = await psi.computeIntersection(
    session,
    setup.setupMessage,
    response,
  );

  console.log('\nPSI result:');
  console.log('Matches found:', result.cardinality);
  console.log('Match token:  ', result.intersection[0]?.slice(0, 16) + '...');
  console.log('Is alice-bob? ', result.intersection[0] === aliceSelectsBob);
  console.log('\nBob learned about the mutual match with Alice.');
  console.log('Bob did NOT learn that Alice also selected Carol.');
}

main().catch(console.error);
