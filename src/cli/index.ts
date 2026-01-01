#!/usr/bin/env node
/**
 * Rendezvous CLI - Private Mutual Matching
 *
 * Commands:
 * - create: Create a new matching pool
 * - list: List all pools
 * - show: Show pool details
 * - submit: Submit preferences to a pool
 * - reveal: Reveal committed preferences
 * - matches: Discover your matches (local computation)
 * - close: Close a pool and trigger detection
 * - export: Export pool results
 * - keygen: Generate a new keypair
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import {
  createRendezvous,
  Rendezvous,
  generateKeypair,
  generateSigningKeypair,
  deriveMatchToken,
  deriveMatchTokens,
  deriveNullifier,
  commitTokens,
  Pool,
  PoolStatus,
} from '../rendezvous/index.js';

// Default data directory
const DATA_DIR = process.env.RENDEZVOUS_DATA_DIR || './data';
const DB_PATH = path.join(DATA_DIR, 'rendezvous.db');

// Ensure data directory exists
function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// Get Rendezvous instance
function getRendezvous(): Rendezvous {
  ensureDataDir();
  return createRendezvous(DB_PATH);
}

// Format duration
function formatDuration(ms: number): string {
  if (ms < 0) return 'expired';

  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);

  if (hours > 24) {
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    return `${days}d ${remainingHours}h`;
  }

  return `${hours}h ${minutes}m`;
}

// Format status with color
function formatStatus(status: PoolStatus): string {
  const colors: Record<PoolStatus, string> = {
    open: '\x1b[32m',    // Green
    commit: '\x1b[33m',  // Yellow
    reveal: '\x1b[36m',  // Cyan
    closed: '\x1b[90m',  // Gray
  };
  const reset = '\x1b[0m';
  return `${colors[status]}${status}${reset}`;
}

// Interactive prompt
function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// Create CLI program
const program = new Command();

program
  .name('rendezvous')
  .description('Private mutual matching - Find mutual interest without revealing unilateral preferences')
  .version('0.1.0');

// ============================================================================
// Pool Management Commands
// ============================================================================

program
  .command('create')
  .description('Create a new matching pool')
  .argument('<name>', 'Pool name')
  .option('-d, --deadline <date>', 'Reveal deadline (ISO date or hours from now)')
  .option('-c, --commit-phase', 'Enable commit-reveal phases')
  .option('-m, --max-preferences <n>', 'Max preferences per participant', parseInt)
  .option('-k, --creator-key <key>', 'Creator public key (hex)')
  .option('--description <text>', 'Pool description')
  .action(async (name: string, options) => {
    const rv = getRendezvous();

    try {
      // Parse deadline
      let revealDeadline: Date;
      if (options.deadline) {
        if (/^\d+$/.test(options.deadline)) {
          // Hours from now
          const hours = parseInt(options.deadline, 10);
          revealDeadline = new Date(Date.now() + hours * 3600000);
        } else {
          // ISO date
          revealDeadline = new Date(options.deadline);
        }
      } else {
        // Default: 24 hours
        revealDeadline = new Date(Date.now() + 24 * 3600000);
      }

      // Commit deadline (if enabled, 6 hours before reveal)
      let commitDeadline: Date | undefined;
      if (options.commitPhase) {
        const commitWindow = Math.min(6 * 3600000, revealDeadline.getTime() - Date.now() - 3600000);
        commitDeadline = new Date(revealDeadline.getTime() - Math.max(commitWindow, 3600000));
      }

      // Creator keys (generate if not provided)
      let creatorKey = options.creatorKey;
      let signingKey: string;
      if (!creatorKey) {
        const keypair = generateKeypair();
        const signingKeypair = generateSigningKeypair();
        creatorKey = keypair.publicKey;
        signingKey = signingKeypair.signingPublicKey;
        console.log(`Generated creator keypairs:`);
        console.log(`  X25519 Public:  ${keypair.publicKey}`);
        console.log(`  X25519 Private: ${keypair.privateKey}`);
        console.log(`  Ed25519 Public:  ${signingKeypair.signingPublicKey}`);
        console.log(`  Ed25519 Private: ${signingKeypair.signingPrivateKey}`);
        console.log(`  (Save the private keys securely!)\n`);
      } else {
        const signingKeypair = generateSigningKeypair();
        signingKey = signingKeypair.signingPublicKey;
        console.log(`Generated signing keypair:`);
        console.log(`  Ed25519 Public:  ${signingKeypair.signingPublicKey}`);
        console.log(`  Ed25519 Private: ${signingKeypair.signingPrivateKey}`);
        console.log(`  (Save the private key securely!)\n`);
      }

      const pool = rv.createPool({
        name,
        description: options.description,
        creatorPublicKey: creatorKey,
        creatorSigningKey: signingKey,
        commitDeadline,
        revealDeadline,
        maxPreferencesPerParticipant: options.maxPreferences,
      });

      console.log(`Pool created successfully!`);
      console.log(`  ID: ${pool.id}`);
      console.log(`  Name: ${pool.name}`);
      console.log(`  Status: ${formatStatus(pool.status)}`);
      if (pool.commitDeadline) {
        console.log(`  Commit deadline: ${pool.commitDeadline.toISOString()}`);
      }
      console.log(`  Reveal deadline: ${pool.revealDeadline.toISOString()}`);
      if (pool.maxPreferencesPerParticipant) {
        console.log(`  Max preferences: ${pool.maxPreferencesPerParticipant}`);
      }
    } finally {
      rv.close();
    }
  });

program
  .command('list')
  .description('List all pools')
  .option('-s, --status <status>', 'Filter by status (open, commit, reveal, closed)')
  .option('-n, --limit <n>', 'Limit results', parseInt, 20)
  .action((options) => {
    const rv = getRendezvous();

    try {
      const pools = rv.listPools({
        status: options.status as PoolStatus | undefined,
        limit: options.limit,
      });

      if (pools.length === 0) {
        console.log('No pools found.');
        return;
      }

      console.log(`Found ${pools.length} pool(s):\n`);

      for (const pool of pools) {
        const phase = rv.getPoolPhase(pool.id);
        const timeLeft = formatDuration(phase.remainingMs);

        console.log(`${pool.id}`);
        console.log(`  Name: ${pool.name}`);
        console.log(`  Status: ${formatStatus(phase.currentPhase)} (${timeLeft} remaining)`);
        console.log('');
      }
    } finally {
      rv.close();
    }
  });

program
  .command('show')
  .description('Show pool details')
  .argument('<pool-id>', 'Pool ID')
  .action((poolId: string) => {
    const rv = getRendezvous();

    try {
      const pool = rv.getPool(poolId);
      if (!pool) {
        console.error(`Pool not found: ${poolId}`);
        process.exit(1);
      }

      const phase = rv.getPoolPhase(poolId);

      console.log(`Pool: ${pool.name}`);
      console.log(`ID: ${pool.id}`);
      console.log(`Description: ${pool.description || '(none)'}`);
      console.log(`Creator: ${pool.creatorPublicKey}`);
      console.log(`Status: ${formatStatus(phase.currentPhase)}`);
      console.log('');
      console.log('Timing:');
      if (pool.commitDeadline) {
        console.log(`  Commit deadline: ${pool.commitDeadline.toISOString()}`);
      }
      console.log(`  Reveal deadline: ${pool.revealDeadline.toISOString()}`);
      console.log(`  Time remaining: ${formatDuration(phase.remainingMs)}`);
      console.log('');
      console.log('Settings:');
      console.log(`  Commit-reveal: ${pool.commitDeadline ? 'enabled' : 'disabled'}`);
      console.log(`  Max preferences: ${pool.maxPreferencesPerParticipant || 'unlimited'}`);
      console.log(`  Eligibility: ${pool.eligibilityGate.type}`);

      // Show match results if closed
      if (phase.currentPhase === 'closed') {
        const result = rv.getMatchResult(poolId);
        if (result) {
          console.log('');
          console.log('Results:');
          console.log(`  Total submissions: ${result.totalSubmissions}`);
          console.log(`  Unique participants: ${result.uniqueParticipants}`);
          console.log(`  Mutual matches: ${result.matchedTokens.length}`);
        }
      }
    } finally {
      rv.close();
    }
  });

// ============================================================================
// Participation Commands
// ============================================================================

program
  .command('submit')
  .description('Submit preferences to a pool')
  .argument('<pool-id>', 'Pool ID')
  .argument('<their-public-keys...>', 'Public keys of parties you want to match with')
  .option('-k, --private-key <key>', 'Your private key (hex)')
  .option('--key-file <path>', 'Path to file containing your private key')
  .action(async (poolId: string, theirPublicKeys: string[], options) => {
    const rv = getRendezvous();

    try {
      // Get private key
      let privateKey = options.privateKey;
      if (options.keyFile) {
        privateKey = fs.readFileSync(options.keyFile, 'utf-8').trim();
      }
      if (!privateKey) {
        privateKey = await prompt('Enter your private key: ');
      }

      // Derive match tokens
      const matchTokens = deriveMatchTokens(privateKey, theirPublicKeys, poolId);

      // Derive nullifier
      const nullifier = deriveNullifier(privateKey, poolId);

      // Check pool phase
      const pool = rv.getPool(poolId);
      if (!pool) {
        console.error(`Pool not found: ${poolId}`);
        process.exit(1);
      }

      const phase = rv.getPoolPhase(poolId);

      // For commit phase, compute commitments
      let commitHashes: string[] | undefined;
      if (phase.currentPhase === 'commit') {
        commitHashes = commitTokens(matchTokens);
      }

      // Submit
      const result = rv.submitPreferences({
        poolId,
        matchTokens,
        commitHashes,
        nullifier,
      });

      console.log(result.message);
      console.log(`  Phase: ${result.phase}`);
      console.log(`  Preferences: ${result.preferenceIds.length}`);

      if (result.phase === 'commit') {
        console.log('\nIMPORTANT: Save these values for the reveal phase:');
        console.log(`  Private key: ${privateKey}`);
        console.log(`  Selected keys: ${theirPublicKeys.join(', ')}`);
      }
    } catch (error) {
      console.error(`Error: ${(error as Error).message}`);
      process.exit(1);
    } finally {
      rv.close();
    }
  });

program
  .command('reveal')
  .description('Reveal previously committed preferences')
  .argument('<pool-id>', 'Pool ID')
  .argument('<their-public-keys...>', 'Public keys you originally selected (same as submit)')
  .option('-k, --private-key <key>', 'Your private key (hex)')
  .option('--key-file <path>', 'Path to file containing your private key')
  .action(async (poolId: string, theirPublicKeys: string[], options) => {
    const rv = getRendezvous();

    try {
      // Get private key
      let privateKey = options.privateKey;
      if (options.keyFile) {
        privateKey = fs.readFileSync(options.keyFile, 'utf-8').trim();
      }
      if (!privateKey) {
        privateKey = await prompt('Enter your private key: ');
      }

      // Derive match tokens (must be same as during commit)
      const matchTokens = deriveMatchTokens(privateKey, theirPublicKeys, poolId);

      // Derive nullifier
      const nullifier = deriveNullifier(privateKey, poolId);

      // Reveal
      const result = rv.revealPreferences({
        poolId,
        matchTokens,
        nullifier,
      });

      console.log(result.message);
      console.log(`  Revealed: ${result.revealedCount} preferences`);
    } catch (error) {
      console.error(`Error: ${(error as Error).message}`);
      process.exit(1);
    } finally {
      rv.close();
    }
  });

program
  .command('matches')
  .description('Discover your matches in a pool (local computation)')
  .argument('<pool-id>', 'Pool ID')
  .argument('<their-public-keys...>', 'Public keys you selected')
  .option('-k, --private-key <key>', 'Your private key (hex)')
  .option('--key-file <path>', 'Path to file containing your private key')
  .action(async (poolId: string, theirPublicKeys: string[], options) => {
    const rv = getRendezvous();

    try {
      // Get private key
      let privateKey = options.privateKey;
      if (options.keyFile) {
        privateKey = fs.readFileSync(options.keyFile, 'utf-8').trim();
      }
      if (!privateKey) {
        privateKey = await prompt('Enter your private key: ');
      }

      // Check if results are available
      const result = rv.getMatchResult(poolId);
      if (!result) {
        console.error('Match results not yet available. Pool may not be closed.');
        process.exit(1);
      }

      // Discover matches (local computation)
      const matches = rv.discoverMyMatches(poolId, privateKey, theirPublicKeys);

      if (matches.length === 0) {
        console.log('No mutual matches found.');
        console.log(`  You selected: ${theirPublicKeys.length} parties`);
        console.log(`  Total matches in pool: ${result.matchedTokens.length}`);
      } else {
        console.log(`Found ${matches.length} mutual match(es)!\n`);
        for (const match of matches) {
          console.log(`  Matched with: ${match.matchedPublicKey}`);
        }
      }
    } catch (error) {
      console.error(`Error: ${(error as Error).message}`);
      process.exit(1);
    } finally {
      rv.close();
    }
  });

// ============================================================================
// Admin Commands
// ============================================================================

program
  .command('close')
  .description('Close a pool and trigger match detection')
  .argument('<pool-id>', 'Pool ID')
  .action(async (poolId: string) => {
    const rv = getRendezvous();

    try {
      // Close the pool
      rv.closePool(poolId);
      console.log('Pool closed.');

      // Detect matches
      const result = await rv.detectMatches(poolId);

      console.log('\nMatch Detection Results:');
      console.log(`  Total submissions: ${result.totalSubmissions}`);
      console.log(`  Unique participants: ${result.uniqueParticipants}`);
      console.log(`  Mutual matches found: ${result.matchedTokens.length}`);
      console.log(`  Detected at: ${result.detectedAt.toISOString()}`);
    } catch (error) {
      console.error(`Error: ${(error as Error).message}`);
      process.exit(1);
    } finally {
      rv.close();
    }
  });

program
  .command('export')
  .description('Export pool results')
  .argument('<pool-id>', 'Pool ID')
  .option('-o, --output <path>', 'Output file path')
  .option('-f, --format <format>', 'Output format (json, csv)', 'json')
  .action((poolId: string, options) => {
    const rv = getRendezvous();

    try {
      const pool = rv.getPool(poolId);
      if (!pool) {
        console.error(`Pool not found: ${poolId}`);
        process.exit(1);
      }

      const result = rv.getMatchResult(poolId);
      if (!result) {
        console.error('No match results available. Close the pool first.');
        process.exit(1);
      }

      const stats = rv.getMatchStats(poolId);

      const exportData = {
        pool: {
          id: pool.id,
          name: pool.name,
          description: pool.description,
          revealDeadline: pool.revealDeadline.toISOString(),
          status: pool.status,
        },
        results: {
          totalSubmissions: result.totalSubmissions,
          uniqueParticipants: result.uniqueParticipants,
          mutualMatches: result.matchedTokens.length,
          matchRate: stats.matchRate,
          detectedAt: result.detectedAt.toISOString(),
        },
        matchedTokens: result.matchedTokens,
      };

      let output: string;
      if (options.format === 'csv') {
        output = `pool_id,name,total_submissions,unique_participants,mutual_matches,match_rate,detected_at\n`;
        output += `${pool.id},"${pool.name}",${result.totalSubmissions},${result.uniqueParticipants},${result.matchedTokens.length},${stats.matchRate.toFixed(4)},${result.detectedAt.toISOString()}\n`;
      } else {
        output = JSON.stringify(exportData, null, 2);
      }

      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`Results exported to: ${options.output}`);
      } else {
        console.log(output);
      }
    } finally {
      rv.close();
    }
  });

// ============================================================================
// Utility Commands
// ============================================================================

program
  .command('keygen')
  .description('Generate a new X25519 keypair')
  .option('-o, --output <path>', 'Save private key to file')
  .action((options) => {
    const keypair = generateKeypair();

    console.log('Generated X25519 keypair:');
    console.log(`  Public key:  ${keypair.publicKey}`);
    console.log(`  Private key: ${keypair.privateKey}`);

    if (options.output) {
      fs.writeFileSync(options.output, keypair.privateKey, { mode: 0o600 });
      console.log(`\nPrivate key saved to: ${options.output}`);
    }

    console.log('\nKeep your private key secret!');
  });

program
  .command('derive-token')
  .description('Derive a match token (for debugging)')
  .argument('<pool-id>', 'Pool ID')
  .argument('<their-public-key>', 'Their public key')
  .option('-k, --private-key <key>', 'Your private key (hex)')
  .action(async (poolId: string, theirPublicKey: string, options) => {
    let privateKey = options.privateKey;
    if (!privateKey) {
      privateKey = await prompt('Enter your private key: ');
    }

    const token = deriveMatchToken(privateKey, theirPublicKey, poolId);
    const nullifier = deriveNullifier(privateKey, poolId);

    console.log(`Pool ID: ${poolId}`);
    console.log(`Their key: ${theirPublicKey}`);
    console.log(`Match token: ${token}`);
    console.log(`Nullifier: ${nullifier}`);
  });

// Parse arguments
program.parse();
