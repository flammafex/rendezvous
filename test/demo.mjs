#!/usr/bin/env node
/**
 * Rendezvous MVP Demo
 *
 * Demonstrates the complete workflow:
 * 1. Create participants with keypairs
 * 2. Create a matching pool
 * 3. Submit preferences
 * 4. Close pool and detect matches
 * 5. Local match discovery
 */

import {
  createRendezvous,
  generateKeypair,
  deriveMatchTokens,
  deriveNullifier,
} from './dist/rendezvous/index.js';
import * as fs from 'fs';
import * as path from 'path';

// Ensure data directory exists
const DATA_DIR = './data';
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const rv = createRendezvous(path.join(DATA_DIR, 'rendezvous.db'));

console.log('=== Rendezvous MVP Demo ===\n');

// 1. Generate keypairs for participants
console.log('1. Creating participants...');
const alice = generateKeypair();
const bob = generateKeypair();
const charlie = generateKeypair();
console.log('   Alice: ' + alice.publicKey.slice(0, 16) + '...');
console.log('   Bob: ' + bob.publicKey.slice(0, 16) + '...');
console.log('   Charlie: ' + charlie.publicKey.slice(0, 16) + '...\n');

// 2. Create a matching pool
console.log('2. Creating pool...');
const pool = rv.createPool({
  name: 'Friday Mixer',
  description: 'Find your mutual matches!',
  creatorPublicKey: alice.publicKey,
  revealDeadline: new Date(Date.now() + 24 * 3600000),
  maxPreferencesPerParticipant: 5,
});
console.log('   Pool ID: ' + pool.id);
console.log('   Status: ' + pool.status + '\n');

// 3. Submit preferences
console.log('3. Submitting preferences...');

// Alice selects Bob and Charlie
const aliceTokens = deriveMatchTokens(alice.privateKey, [bob.publicKey, charlie.publicKey], pool.id);
rv.submitPreferences({
  poolId: pool.id,
  matchTokens: aliceTokens,
  nullifier: deriveNullifier(alice.privateKey, pool.id),
});
console.log('   Alice selects: Bob, Charlie');

// Bob selects Alice (MUTUAL!)
const bobTokens = deriveMatchTokens(bob.privateKey, [alice.publicKey], pool.id);
rv.submitPreferences({
  poolId: pool.id,
  matchTokens: bobTokens,
  nullifier: deriveNullifier(bob.privateKey, pool.id),
});
console.log('   Bob selects: Alice');

// Charlie selects Bob (NOT Alice - no mutual match with Alice)
const charlieTokens = deriveMatchTokens(charlie.privateKey, [bob.publicKey], pool.id);
rv.submitPreferences({
  poolId: pool.id,
  matchTokens: charlieTokens,
  nullifier: deriveNullifier(charlie.privateKey, pool.id),
});
console.log('   Charlie selects: Bob\n');

// 4. Close pool and detect matches
console.log('4. Closing pool and detecting matches...');
rv.closePool(pool.id);
const result = rv.detectMatches(pool.id);
console.log('   Total submissions: ' + result.totalSubmissions);
console.log('   Unique participants: ' + result.uniqueParticipants);
console.log('   Mutual matches found: ' + result.matchedTokens.length + '\n');

// 5. Each participant discovers their matches locally
console.log('5. Local match discovery...');

const aliceMatches = rv.discoverMyMatches(pool.id, alice.privateKey, [bob.publicKey, charlie.publicKey]);
console.log('   Alice matched with ' + aliceMatches.length + ' person(s):');
if (aliceMatches.some(m => m.matchedPublicKey === bob.publicKey)) {
  console.log('     - Bob (mutual!)');
}
if (aliceMatches.some(m => m.matchedPublicKey === charlie.publicKey)) {
  console.log('     - Charlie (mutual!)');
} else {
  console.log('     - NOT Charlie (he didn\'t select Alice back)');
}

const bobMatches = rv.discoverMyMatches(pool.id, bob.privateKey, [alice.publicKey]);
console.log('   Bob matched with ' + bobMatches.length + ' person(s):');
if (bobMatches.some(m => m.matchedPublicKey === alice.publicKey)) {
  console.log('     - Alice (mutual!)');
}

const charlieMatches = rv.discoverMyMatches(pool.id, charlie.privateKey, [bob.publicKey]);
console.log('   Charlie matched with ' + charlieMatches.length + ' person(s):');
if (charlieMatches.length === 0) {
  console.log('     - Bob did not select Charlie back');
}

// 6. Verify integrity
console.log('\n6. Verifying match integrity...');
const verification = rv.verifyMatchIntegrity(pool.id);
console.log('   Integrity check: ' + (verification.valid ? 'PASSED' : 'FAILED'));

// 7. Show stats
console.log('\n7. Pool statistics...');
const stats = rv.getMatchStats(pool.id);
console.log('   Total participants: ' + stats.totalParticipants);
console.log('   Total preferences: ' + stats.totalPreferences);
console.log('   Mutual matches: ' + stats.mutualMatches);
console.log('   Unilateral selections: ' + stats.unilateralSelections);
console.log('   Match rate: ' + (stats.matchRate * 100).toFixed(1) + '%');

rv.close();
console.log('\n=== MVP Demo Complete! ===');
console.log('\nKey privacy property demonstrated:');
console.log('  - Alice knows she matched with Bob');
console.log('  - Alice knows she did NOT match with Charlie');
console.log('  - But Charlie cannot learn that Alice selected him!');
console.log('  - And Bob cannot learn that Charlie also selected him!');
