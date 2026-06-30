import { generateKeypair, deriveMatchToken } from '../../../src/matchlock/dh/index.js';
import { decryptWithPrivateKey, deserializeEncryptedBox } from '../../../src/matchlock/dh/ecies.js';
import { PsiService } from '../../../src/matchlock/psi/service.js';

describe('PsiService — owner-held key flow', () => {
  let psi: PsiService;

  beforeAll(async () => {
    psi = new PsiService();
    await psi.init();
  }, 60000);

  it('full owner-held key round-trip using derived match tokens', async () => {
    // Simulate: alice owns a pool, bob/carol/dave are candidates
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const dave = generateKeypair();
    const poolId = 'test-pool';

    const ownerTokens = [
      deriveMatchToken(alice.privateKey, bob.publicKey, poolId),
      deriveMatchToken(alice.privateKey, carol.publicKey, poolId),
      deriveMatchToken(alice.privateKey, dave.publicKey, poolId),
    ];

    const setup = await psi.createOwnerEncryptedSetup(
      { poolId, matchTokens: ownerTokens },
      alice.publicKey,
    );

    expect(setup.encryptedServerKey).toBeTruthy();
    expect(setup.setupMessage).toBeTruthy();
    expect(setup.ownerPublicKey).toBe(alice.publicKey);

    // Joiner (bob) derives his token for alice — must equal ownerTokens[0] by commutativity
    const bobTokenForAlice = deriveMatchToken(bob.privateKey, alice.publicKey, poolId);
    const eve = generateKeypair(); // no mutual match with alice
    const joinerTokens = [
      bobTokenForAlice,
      deriveMatchToken(eve.privateKey, alice.publicKey, poolId),
    ];

    const { request: psiRequest, session } = await psi.createRequest(joinerTokens);

    const box = deserializeEncryptedBox(setup.encryptedServerKey);
    const decryptedServerKey = decryptWithPrivateKey(box, alice.privateKey);
    const psiResponse = await psi.processRequestWithDecryptedKey(decryptedServerKey, psiRequest);

    const result = await psi.computeIntersection(session, setup.setupMessage, psiResponse);

    expect(result.intersection).toContain(bobTokenForAlice);
    expect(result.cardinality).toBe(1);
  }, 60000);

  it('cardinality-only mode with derived tokens', async () => {
    const alice = generateKeypair();
    const bob = generateKeypair();
    const carol = generateKeypair();
    const dave = generateKeypair();
    const poolId = 'test-pool-2';

    const ownerTokens = [
      deriveMatchToken(alice.privateKey, bob.publicKey, poolId),
      deriveMatchToken(alice.privateKey, carol.publicKey, poolId),
      deriveMatchToken(alice.privateKey, dave.publicKey, poolId),
    ];

    const setup = await psi.createOwnerEncryptedSetup(
      { poolId, matchTokens: ownerTokens },
      alice.publicKey,
    );

    // Bob and carol both match alice; eve does not
    const eve = generateKeypair();
    const joinerTokens = [
      deriveMatchToken(bob.privateKey, alice.publicKey, poolId),
      deriveMatchToken(carol.privateKey, alice.publicKey, poolId),
      deriveMatchToken(eve.privateKey, alice.publicKey, poolId),
    ];

    const { request, session } = await psi.createRequest(joinerTokens);
    const box = deserializeEncryptedBox(setup.encryptedServerKey);
    const serverKey = decryptWithPrivateKey(box, alice.privateKey);
    const response = await psi.processRequestWithDecryptedKey(serverKey, request);

    const count = await psi.computeCardinality(session, setup.setupMessage, response);
    expect(count).toBe(2);
  }, 60000);

  it('session inputs are frozen (immutable)', async () => {
    const { session } = await psi.createRequest(['a', 'b']);
    expect(Object.isFrozen(session.inputs)).toBe(true);
  });
});
