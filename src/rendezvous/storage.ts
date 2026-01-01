/**
 * Rendezvous - Private Mutual Matching
 * Storage layer with SQLite and in-memory implementations
 */

import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import {
  Pool,
  Preference,
  MatchResult,
  Participant,
  PoolFilter,
  PreferenceFilter,
  ParticipantFilter,
  PoolStatus,
  VoterGate,
  FreebirdProof,
  WitnessProof,
} from './types.js';
import {
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
} from '../psi/types.js';

// ============================================================================
// Storage Interface
// ============================================================================

/**
 * Abstract storage interface for Rendezvous data.
 * Implementations can use SQLite, in-memory, or other backends.
 */
export interface RendezvousStore {
  // Pool operations
  insertPool(pool: Pool): void;
  getPool(id: string): Pool | undefined;
  getPools(filter?: PoolFilter): Pool[];
  updatePoolStatus(id: string, status: PoolStatus): void;

  // Participant operations
  insertParticipant(participant: Participant): void;
  getParticipant(id: string): Participant | undefined;
  getParticipantByPublicKey(poolId: string, publicKey: string): Participant | undefined;
  getParticipants(filter: ParticipantFilter): Participant[];
  getParticipantsByPoolId(poolId: string): Participant[];
  countParticipantsByPoolId(poolId: string): number;
  deleteParticipantsByPoolId(poolId: string): number;

  // Preference operations
  insertPreference(preference: Preference): void;
  getPreference(id: string): Preference | undefined;
  getPreferences(filter: PreferenceFilter): Preference[];
  getPreferencesByPoolId(poolId: string): Preference[];
  getPreferencesByNullifier(poolId: string, nullifier: string): Preference[];
  updatePreferenceRevealed(id: string, matchToken: string): void;
  countPreferencesByNullifier(poolId: string, nullifier: string): number;

  // Match result operations
  insertMatchResult(result: MatchResult): void;
  getMatchResult(poolId: string): MatchResult | undefined;

  // Token counting for match detection
  countTokenOccurrences(poolId: string): Map<string, number>;

  // PSI Setup operations (owner-held keys)
  insertPsiSetup(setup: OwnerHeldPsiSetup): void;
  getPsiSetup(poolId: string): OwnerHeldPsiSetup | undefined;

  // PSI Request operations (pending queue)
  insertPsiRequest(request: PendingPsiRequest): void;
  getPsiRequest(id: string): PendingPsiRequest | undefined;
  getPendingPsiRequestsByPool(poolId: string): PendingPsiRequest[];
  updatePsiRequestStatus(id: string, status: PendingPsiRequest['status']): void;

  // PSI Response operations
  insertPsiResponse(response: PsiResponseRecord): void;
  getPsiResponse(requestId: string): PsiResponseRecord | undefined;

  // Cleanup
  close(): void;
}

// ============================================================================
// SQLite Implementation
// ============================================================================

/**
 * SQLite-based storage implementation.
 * Uses WAL mode for better concurrent access.
 */
export class SQLiteStore implements RendezvousStore {
  private db: Database.Database;

  constructor(dbPath: string = ':memory:') {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      -- Pools table
      CREATE TABLE IF NOT EXISTS pools (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        creatorPublicKey TEXT NOT NULL,
        creatorSigningKey TEXT,
        commitDeadline INTEGER,
        revealDeadline INTEGER NOT NULL,
        eligibilityGate TEXT NOT NULL,
        maxPreferencesPerParticipant INTEGER,
        ephemeral INTEGER DEFAULT 0,
        requiresInviteToJoin INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'open',
        createdAt INTEGER NOT NULL,
        updatedAt INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pools_status ON pools(status);
      CREATE INDEX IF NOT EXISTS idx_pools_creator ON pools(creatorPublicKey);

      -- Preferences table
      CREATE TABLE IF NOT EXISTS preferences (
        id TEXT PRIMARY KEY,
        poolId TEXT NOT NULL,
        matchToken TEXT NOT NULL,
        commitHash TEXT,
        revealed INTEGER NOT NULL DEFAULT 0,
        submittedAt INTEGER NOT NULL,
        eligibilityProof TEXT,
        nullifier TEXT NOT NULL,
        encryptedReveal TEXT,
        FOREIGN KEY(poolId) REFERENCES pools(id)
      );
      CREATE INDEX IF NOT EXISTS idx_preferences_pool ON preferences(poolId);
      CREATE INDEX IF NOT EXISTS idx_preferences_token ON preferences(poolId, matchToken);
      CREATE INDEX IF NOT EXISTS idx_preferences_nullifier ON preferences(poolId, nullifier);
      CREATE INDEX IF NOT EXISTS idx_preferences_commit ON preferences(poolId, commitHash);

      -- Participants table
      CREATE TABLE IF NOT EXISTS participants (
        id TEXT PRIMARY KEY,
        poolId TEXT NOT NULL,
        publicKey TEXT NOT NULL,
        displayName TEXT NOT NULL,
        bio TEXT,
        avatarUrl TEXT,
        profileData TEXT,
        registeredAt INTEGER NOT NULL,
        FOREIGN KEY(poolId) REFERENCES pools(id),
        UNIQUE(poolId, publicKey)
      );
      CREATE INDEX IF NOT EXISTS idx_participants_pool ON participants(poolId);
      CREATE INDEX IF NOT EXISTS idx_participants_key ON participants(poolId, publicKey);

      -- Match results table
      CREATE TABLE IF NOT EXISTS match_results (
        id TEXT PRIMARY KEY,
        poolId TEXT NOT NULL UNIQUE,
        matchedTokens TEXT NOT NULL,
        totalSubmissions INTEGER NOT NULL,
        uniqueParticipants INTEGER NOT NULL,
        detectedAt INTEGER NOT NULL,
        witnessProof TEXT,
        FOREIGN KEY(poolId) REFERENCES pools(id)
      );
      CREATE INDEX IF NOT EXISTS idx_results_pool ON match_results(poolId);

      -- PSI setups with owner-encrypted keys (server cannot decrypt)
      CREATE TABLE IF NOT EXISTS psi_setups (
        id TEXT PRIMARY KEY,
        poolId TEXT NOT NULL UNIQUE,
        setupMessage TEXT NOT NULL,
        encryptedServerKey TEXT NOT NULL,
        ownerPublicKey TEXT NOT NULL,
        fpr REAL NOT NULL,
        maxClientElements INTEGER NOT NULL,
        dataStructure TEXT NOT NULL,
        createdAt INTEGER NOT NULL,
        FOREIGN KEY(poolId) REFERENCES pools(id)
      );
      CREATE INDEX IF NOT EXISTS idx_psi_setups_pool ON psi_setups(poolId);

      -- Pending PSI requests (queued for owner processing)
      CREATE TABLE IF NOT EXISTS psi_requests (
        id TEXT PRIMARY KEY,
        poolId TEXT NOT NULL,
        psiRequest TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        authTokenHash TEXT,
        createdAt INTEGER NOT NULL,
        FOREIGN KEY(poolId) REFERENCES pools(id)
      );
      CREATE INDEX IF NOT EXISTS idx_psi_requests_pool_status ON psi_requests(poolId, status);

      -- PSI responses from owner
      CREATE TABLE IF NOT EXISTS psi_responses (
        id TEXT PRIMARY KEY,
        requestId TEXT NOT NULL UNIQUE,
        poolId TEXT NOT NULL,
        psiSetup TEXT NOT NULL,
        psiResponse TEXT NOT NULL,
        createdAt INTEGER NOT NULL,
        expiresAt INTEGER NOT NULL,
        FOREIGN KEY(requestId) REFERENCES psi_requests(id),
        FOREIGN KEY(poolId) REFERENCES pools(id)
      );
      CREATE INDEX IF NOT EXISTS idx_psi_responses_request ON psi_responses(requestId);
    `);
  }

  // Pool operations

  insertPool(pool: Pool): void {
    const stmt = this.db.prepare(`
      INSERT INTO pools (
        id, name, description, creatorPublicKey, creatorSigningKey, commitDeadline,
        revealDeadline, eligibilityGate, maxPreferencesPerParticipant,
        ephemeral, requiresInviteToJoin, status, createdAt, updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      pool.id,
      pool.name,
      pool.description || null,
      pool.creatorPublicKey,
      pool.creatorSigningKey || null,
      pool.commitDeadline ? pool.commitDeadline.getTime() : null,
      pool.revealDeadline.getTime(),
      JSON.stringify(pool.eligibilityGate),
      pool.maxPreferencesPerParticipant || null,
      pool.ephemeral ? 1 : 0,
      pool.requiresInviteToJoin ? 1 : 0,
      pool.status,
      pool.createdAt.getTime(),
      pool.updatedAt.getTime(),
    );
  }

  getPool(id: string): Pool | undefined {
    const stmt = this.db.prepare('SELECT * FROM pools WHERE id = ?');
    const row = stmt.get(id) as PoolRow | undefined;
    return row ? this.rowToPool(row) : undefined;
  }

  getPools(filter?: PoolFilter): Pool[] {
    let query = 'SELECT * FROM pools WHERE 1=1';
    const params: unknown[] = [];

    if (filter?.status) {
      query += ' AND status = ?';
      params.push(filter.status);
    }

    if (filter?.creatorPublicKey) {
      query += ' AND creatorPublicKey = ?';
      params.push(filter.creatorPublicKey);
    }

    query += ' ORDER BY createdAt DESC';

    if (filter?.limit) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }

    if (filter?.offset) {
      query += ' OFFSET ?';
      params.push(filter.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as PoolRow[];
    return rows.map((row) => this.rowToPool(row));
  }

  updatePoolStatus(id: string, status: PoolStatus): void {
    const stmt = this.db.prepare(`
      UPDATE pools SET status = ?, updatedAt = ? WHERE id = ?
    `);
    stmt.run(status, Date.now(), id);
  }

  // Participant operations

  insertParticipant(participant: Participant): void {
    const stmt = this.db.prepare(`
      INSERT INTO participants (
        id, poolId, publicKey, displayName, bio, avatarUrl, profileData, registeredAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      participant.id,
      participant.poolId,
      participant.publicKey,
      participant.displayName,
      participant.bio || null,
      participant.avatarUrl || null,
      participant.profileData ? JSON.stringify(participant.profileData) : null,
      participant.registeredAt.getTime(),
    );
  }

  getParticipant(id: string): Participant | undefined {
    const stmt = this.db.prepare('SELECT * FROM participants WHERE id = ?');
    const row = stmt.get(id) as ParticipantRow | undefined;
    return row ? this.rowToParticipant(row) : undefined;
  }

  getParticipantByPublicKey(poolId: string, publicKey: string): Participant | undefined {
    const stmt = this.db.prepare('SELECT * FROM participants WHERE poolId = ? AND publicKey = ?');
    const row = stmt.get(poolId, publicKey) as ParticipantRow | undefined;
    return row ? this.rowToParticipant(row) : undefined;
  }

  getParticipants(filter: ParticipantFilter): Participant[] {
    let query = 'SELECT * FROM participants WHERE 1=1';
    const params: unknown[] = [];

    if (filter.poolId) {
      query += ' AND poolId = ?';
      params.push(filter.poolId);
    }

    if (filter.publicKey) {
      query += ' AND publicKey = ?';
      params.push(filter.publicKey);
    }

    query += ' ORDER BY registeredAt ASC';

    if (filter.limit) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }

    if (filter.offset) {
      query += ' OFFSET ?';
      params.push(filter.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as ParticipantRow[];
    return rows.map((row) => this.rowToParticipant(row));
  }

  getParticipantsByPoolId(poolId: string): Participant[] {
    return this.getParticipants({ poolId });
  }

  countParticipantsByPoolId(poolId: string): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM participants WHERE poolId = ?
    `);
    const row = stmt.get(poolId) as { count: number };
    return row.count;
  }

  deleteParticipantsByPoolId(poolId: string): number {
    const stmt = this.db.prepare(`
      DELETE FROM participants WHERE poolId = ?
    `);
    const result = stmt.run(poolId);
    return result.changes;
  }

  // Preference operations

  insertPreference(preference: Preference): void {
    const stmt = this.db.prepare(`
      INSERT INTO preferences (
        id, poolId, matchToken, commitHash, revealed,
        submittedAt, eligibilityProof, nullifier, encryptedReveal
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      preference.id,
      preference.poolId,
      preference.matchToken,
      preference.commitHash || null,
      preference.revealed ? 1 : 0,
      preference.submittedAt.getTime(),
      preference.eligibilityProof ? JSON.stringify(preference.eligibilityProof) : null,
      preference.nullifier,
      preference.encryptedReveal || null,
    );
  }

  getPreference(id: string): Preference | undefined {
    const stmt = this.db.prepare('SELECT * FROM preferences WHERE id = ?');
    const row = stmt.get(id) as PreferenceRow | undefined;
    return row ? this.rowToPreference(row) : undefined;
  }

  getPreferences(filter: PreferenceFilter): Preference[] {
    let query = 'SELECT * FROM preferences WHERE 1=1';
    const params: unknown[] = [];

    if (filter.poolId) {
      query += ' AND poolId = ?';
      params.push(filter.poolId);
    }

    if (filter.nullifier) {
      query += ' AND nullifier = ?';
      params.push(filter.nullifier);
    }

    if (filter.revealed !== undefined) {
      query += ' AND revealed = ?';
      params.push(filter.revealed ? 1 : 0);
    }

    query += ' ORDER BY submittedAt ASC';

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as PreferenceRow[];
    return rows.map((row) => this.rowToPreference(row));
  }

  getPreferencesByPoolId(poolId: string): Preference[] {
    return this.getPreferences({ poolId });
  }

  getPreferencesByNullifier(poolId: string, nullifier: string): Preference[] {
    return this.getPreferences({ poolId, nullifier });
  }

  updatePreferenceRevealed(id: string, matchToken: string): void {
    const stmt = this.db.prepare(`
      UPDATE preferences SET revealed = 1, matchToken = ? WHERE id = ?
    `);
    stmt.run(matchToken, id);
  }

  countPreferencesByNullifier(poolId: string, nullifier: string): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM preferences
      WHERE poolId = ? AND nullifier = ?
    `);
    const row = stmt.get(poolId, nullifier) as { count: number };
    return row.count;
  }

  // Match result operations

  insertMatchResult(result: MatchResult): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO match_results (
        id, poolId, matchedTokens, totalSubmissions,
        uniqueParticipants, detectedAt, witnessProof
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      uuidv4(),
      result.poolId,
      JSON.stringify(result.matchedTokens),
      result.totalSubmissions,
      result.uniqueParticipants,
      result.detectedAt.getTime(),
      result.witnessProof ? JSON.stringify(result.witnessProof) : null,
    );
  }

  getMatchResult(poolId: string): MatchResult | undefined {
    const stmt = this.db.prepare('SELECT * FROM match_results WHERE poolId = ?');
    const row = stmt.get(poolId) as MatchResultRow | undefined;
    return row ? this.rowToMatchResult(row) : undefined;
  }

  // Token counting for match detection

  countTokenOccurrences(poolId: string): Map<string, number> {
    const stmt = this.db.prepare(`
      SELECT matchToken, COUNT(*) as count
      FROM preferences
      WHERE poolId = ? AND revealed = 1
      GROUP BY matchToken
    `);

    const rows = stmt.all(poolId) as { matchToken: string; count: number }[];
    const counts = new Map<string, number>();

    for (const row of rows) {
      counts.set(row.matchToken, row.count);
    }

    return counts;
  }

  // PSI Setup operations

  insertPsiSetup(setup: OwnerHeldPsiSetup): void {
    const stmt = this.db.prepare(`
      INSERT INTO psi_setups (
        id, poolId, setupMessage, encryptedServerKey, ownerPublicKey,
        fpr, maxClientElements, dataStructure, createdAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      uuidv4(),
      setup.poolId,
      setup.setupMessage,
      setup.encryptedServerKey,
      setup.ownerPublicKey,
      setup.fpr,
      setup.maxClientElements,
      setup.dataStructure,
      setup.createdAt,
    );
  }

  getPsiSetup(poolId: string): OwnerHeldPsiSetup | undefined {
    const stmt = this.db.prepare('SELECT * FROM psi_setups WHERE poolId = ?');
    const row = stmt.get(poolId) as PsiSetupRow | undefined;
    return row ? this.rowToPsiSetup(row) : undefined;
  }

  // PSI Request operations

  insertPsiRequest(request: PendingPsiRequest): void {
    const stmt = this.db.prepare(`
      INSERT INTO psi_requests (
        id, poolId, psiRequest, status, authTokenHash, createdAt
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      request.id,
      request.poolId,
      request.psiRequest,
      request.status,
      request.authTokenHash || null,
      request.createdAt,
    );
  }

  getPsiRequest(id: string): PendingPsiRequest | undefined {
    const stmt = this.db.prepare('SELECT * FROM psi_requests WHERE id = ?');
    const row = stmt.get(id) as PsiRequestRow | undefined;
    return row ? this.rowToPsiRequest(row) : undefined;
  }

  getPendingPsiRequestsByPool(poolId: string): PendingPsiRequest[] {
    const stmt = this.db.prepare(`
      SELECT * FROM psi_requests
      WHERE poolId = ? AND status = 'pending'
      ORDER BY createdAt ASC
    `);
    const rows = stmt.all(poolId) as PsiRequestRow[];
    return rows.map((row) => this.rowToPsiRequest(row));
  }

  updatePsiRequestStatus(id: string, status: PendingPsiRequest['status']): void {
    const stmt = this.db.prepare(`
      UPDATE psi_requests SET status = ? WHERE id = ?
    `);
    stmt.run(status, id);
  }

  // PSI Response operations

  insertPsiResponse(response: PsiResponseRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO psi_responses (
        id, requestId, poolId, psiSetup, psiResponse, createdAt, expiresAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      response.id,
      response.requestId,
      response.poolId,
      response.psiSetup,
      response.psiResponse,
      response.createdAt,
      response.expiresAt,
    );
  }

  getPsiResponse(requestId: string): PsiResponseRecord | undefined {
    const stmt = this.db.prepare('SELECT * FROM psi_responses WHERE requestId = ?');
    const row = stmt.get(requestId) as PsiResponseRow | undefined;
    return row ? this.rowToPsiResponse(row) : undefined;
  }

  close(): void {
    this.db.close();
  }

  // Row conversion helpers

  private rowToPool(row: PoolRow): Pool {
    return {
      id: row.id,
      name: row.name,
      description: row.description || undefined,
      creatorPublicKey: row.creatorPublicKey,
      creatorSigningKey: row.creatorSigningKey,
      commitDeadline: row.commitDeadline ? new Date(row.commitDeadline) : undefined,
      revealDeadline: new Date(row.revealDeadline),
      eligibilityGate: JSON.parse(row.eligibilityGate) as VoterGate,
      maxPreferencesPerParticipant: row.maxPreferencesPerParticipant || undefined,
      ephemeral: row.ephemeral === 1,
      requiresInviteToJoin: row.requiresInviteToJoin === 1,
      status: row.status as PoolStatus,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    };
  }

  private rowToPreference(row: PreferenceRow): Preference {
    return {
      id: row.id,
      poolId: row.poolId,
      matchToken: row.matchToken,
      commitHash: row.commitHash || undefined,
      revealed: row.revealed === 1,
      submittedAt: new Date(row.submittedAt),
      eligibilityProof: row.eligibilityProof
        ? (JSON.parse(row.eligibilityProof) as FreebirdProof)
        : undefined,
      nullifier: row.nullifier,
      encryptedReveal: row.encryptedReveal || undefined,
    };
  }

  private rowToMatchResult(row: MatchResultRow): MatchResult {
    return {
      poolId: row.poolId,
      matchedTokens: JSON.parse(row.matchedTokens) as string[],
      totalSubmissions: row.totalSubmissions,
      uniqueParticipants: row.uniqueParticipants,
      detectedAt: new Date(row.detectedAt),
      witnessProof: row.witnessProof
        ? (JSON.parse(row.witnessProof) as WitnessProof)
        : undefined,
    };
  }

  private rowToParticipant(row: ParticipantRow): Participant {
    return {
      id: row.id,
      poolId: row.poolId,
      publicKey: row.publicKey,
      displayName: row.displayName,
      bio: row.bio || undefined,
      avatarUrl: row.avatarUrl || undefined,
      profileData: row.profileData
        ? (JSON.parse(row.profileData) as Record<string, string>)
        : undefined,
      registeredAt: new Date(row.registeredAt),
    };
  }

  private rowToPsiSetup(row: PsiSetupRow): OwnerHeldPsiSetup {
    return {
      poolId: row.poolId,
      setupMessage: row.setupMessage,
      encryptedServerKey: row.encryptedServerKey,
      ownerPublicKey: row.ownerPublicKey,
      fpr: row.fpr,
      maxClientElements: row.maxClientElements,
      dataStructure: row.dataStructure as 'GCS' | 'BloomFilter',
      createdAt: row.createdAt,
    };
  }

  private rowToPsiRequest(row: PsiRequestRow): PendingPsiRequest {
    return {
      id: row.id,
      poolId: row.poolId,
      psiRequest: row.psiRequest,
      status: row.status as PendingPsiRequest['status'],
      createdAt: row.createdAt,
      authTokenHash: row.authTokenHash || undefined,
    };
  }

  private rowToPsiResponse(row: PsiResponseRow): PsiResponseRecord {
    return {
      id: row.id,
      requestId: row.requestId,
      poolId: row.poolId,
      psiSetup: row.psiSetup,
      psiResponse: row.psiResponse,
      createdAt: row.createdAt,
      expiresAt: row.expiresAt,
    };
  }
}

// Row type definitions for SQLite
interface PoolRow {
  id: string;
  name: string;
  description: string | null;
  creatorPublicKey: string;
  creatorSigningKey: string;
  commitDeadline: number | null;
  revealDeadline: number;
  eligibilityGate: string;
  maxPreferencesPerParticipant: number | null;
  ephemeral: number;
  requiresInviteToJoin: number;
  status: string;
  createdAt: number;
  updatedAt: number;
}

interface PreferenceRow {
  id: string;
  poolId: string;
  matchToken: string;
  commitHash: string | null;
  revealed: number;
  submittedAt: number;
  eligibilityProof: string | null;
  nullifier: string;
  encryptedReveal: string | null;
}

interface MatchResultRow {
  id: string;
  poolId: string;
  matchedTokens: string;
  totalSubmissions: number;
  uniqueParticipants: number;
  detectedAt: number;
  witnessProof: string | null;
}

interface ParticipantRow {
  id: string;
  poolId: string;
  publicKey: string;
  displayName: string;
  bio: string | null;
  avatarUrl: string | null;
  profileData: string | null;
  registeredAt: number;
}

interface PsiSetupRow {
  id: string;
  poolId: string;
  setupMessage: string;
  encryptedServerKey: string;
  ownerPublicKey: string;
  fpr: number;
  maxClientElements: number;
  dataStructure: string;
  createdAt: number;
}

interface PsiRequestRow {
  id: string;
  poolId: string;
  psiRequest: string;
  status: string;
  authTokenHash: string | null;
  createdAt: number;
}

interface PsiResponseRow {
  id: string;
  requestId: string;
  poolId: string;
  psiSetup: string;
  psiResponse: string;
  createdAt: number;
  expiresAt: number;
}

// ============================================================================
// In-Memory Implementation (for testing)
// ============================================================================

/**
 * In-memory storage implementation for testing.
 * No persistence, all data lost on close.
 */
export class InMemoryStore implements RendezvousStore {
  private pools = new Map<string, Pool>();
  private participants = new Map<string, Participant>();
  private preferences = new Map<string, Preference>();
  private matchResults = new Map<string, MatchResult>();
  private psiSetups = new Map<string, OwnerHeldPsiSetup>();
  private psiRequests = new Map<string, PendingPsiRequest>();
  private psiResponses = new Map<string, PsiResponseRecord>();

  // Pool operations

  insertPool(pool: Pool): void {
    this.pools.set(pool.id, { ...pool });
  }

  getPool(id: string): Pool | undefined {
    const pool = this.pools.get(id);
    return pool ? { ...pool } : undefined;
  }

  getPools(filter?: PoolFilter): Pool[] {
    let results = Array.from(this.pools.values());

    if (filter?.status) {
      results = results.filter((p) => p.status === filter.status);
    }

    if (filter?.creatorPublicKey) {
      results = results.filter((p) => p.creatorPublicKey === filter.creatorPublicKey);
    }

    // Sort by creation date descending
    results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    if (filter?.offset) {
      results = results.slice(filter.offset);
    }

    if (filter?.limit) {
      results = results.slice(0, filter.limit);
    }

    return results.map((p) => ({ ...p }));
  }

  updatePoolStatus(id: string, status: PoolStatus): void {
    const pool = this.pools.get(id);
    if (pool) {
      pool.status = status;
      pool.updatedAt = new Date();
    }
  }

  // Participant operations

  insertParticipant(participant: Participant): void {
    this.participants.set(participant.id, { ...participant });
  }

  getParticipant(id: string): Participant | undefined {
    const participant = this.participants.get(id);
    return participant ? { ...participant } : undefined;
  }

  getParticipantByPublicKey(poolId: string, publicKey: string): Participant | undefined {
    for (const participant of this.participants.values()) {
      if (participant.poolId === poolId && participant.publicKey === publicKey) {
        return { ...participant };
      }
    }
    return undefined;
  }

  getParticipants(filter: ParticipantFilter): Participant[] {
    let results = Array.from(this.participants.values());

    if (filter.poolId) {
      results = results.filter((p) => p.poolId === filter.poolId);
    }

    if (filter.publicKey) {
      results = results.filter((p) => p.publicKey === filter.publicKey);
    }

    // Sort by registration time ascending
    results.sort((a, b) => a.registeredAt.getTime() - b.registeredAt.getTime());

    if (filter.offset) {
      results = results.slice(filter.offset);
    }

    if (filter.limit) {
      results = results.slice(0, filter.limit);
    }

    return results.map((p) => ({ ...p }));
  }

  getParticipantsByPoolId(poolId: string): Participant[] {
    return this.getParticipants({ poolId });
  }

  countParticipantsByPoolId(poolId: string): number {
    return this.getParticipantsByPoolId(poolId).length;
  }

  deleteParticipantsByPoolId(poolId: string): number {
    const toDelete = Array.from(this.participants.entries())
      .filter(([, p]) => p.poolId === poolId)
      .map(([id]) => id);
    for (const id of toDelete) {
      this.participants.delete(id);
    }
    return toDelete.length;
  }

  // Preference operations

  insertPreference(preference: Preference): void {
    this.preferences.set(preference.id, { ...preference });
  }

  getPreference(id: string): Preference | undefined {
    const pref = this.preferences.get(id);
    return pref ? { ...pref } : undefined;
  }

  getPreferences(filter: PreferenceFilter): Preference[] {
    let results = Array.from(this.preferences.values());

    if (filter.poolId) {
      results = results.filter((p) => p.poolId === filter.poolId);
    }

    if (filter.nullifier) {
      results = results.filter((p) => p.nullifier === filter.nullifier);
    }

    if (filter.revealed !== undefined) {
      results = results.filter((p) => p.revealed === filter.revealed);
    }

    // Sort by submission time ascending
    results.sort((a, b) => a.submittedAt.getTime() - b.submittedAt.getTime());

    return results.map((p) => ({ ...p }));
  }

  getPreferencesByPoolId(poolId: string): Preference[] {
    return this.getPreferences({ poolId });
  }

  getPreferencesByNullifier(poolId: string, nullifier: string): Preference[] {
    return this.getPreferences({ poolId, nullifier });
  }

  updatePreferenceRevealed(id: string, matchToken: string): void {
    const pref = this.preferences.get(id);
    if (pref) {
      pref.revealed = true;
      pref.matchToken = matchToken;
    }
  }

  countPreferencesByNullifier(poolId: string, nullifier: string): number {
    return this.getPreferencesByNullifier(poolId, nullifier).length;
  }

  // Match result operations

  insertMatchResult(result: MatchResult): void {
    this.matchResults.set(result.poolId, { ...result });
  }

  getMatchResult(poolId: string): MatchResult | undefined {
    const result = this.matchResults.get(poolId);
    return result ? { ...result } : undefined;
  }

  // Token counting for match detection

  countTokenOccurrences(poolId: string): Map<string, number> {
    const counts = new Map<string, number>();
    const prefs = this.getPreferences({ poolId, revealed: true });

    for (const pref of prefs) {
      const current = counts.get(pref.matchToken) || 0;
      counts.set(pref.matchToken, current + 1);
    }

    return counts;
  }

  // PSI Setup operations

  insertPsiSetup(setup: OwnerHeldPsiSetup): void {
    this.psiSetups.set(setup.poolId, { ...setup });
  }

  getPsiSetup(poolId: string): OwnerHeldPsiSetup | undefined {
    const setup = this.psiSetups.get(poolId);
    return setup ? { ...setup } : undefined;
  }

  // PSI Request operations

  insertPsiRequest(request: PendingPsiRequest): void {
    this.psiRequests.set(request.id, { ...request });
  }

  getPsiRequest(id: string): PendingPsiRequest | undefined {
    const request = this.psiRequests.get(id);
    return request ? { ...request } : undefined;
  }

  getPendingPsiRequestsByPool(poolId: string): PendingPsiRequest[] {
    return Array.from(this.psiRequests.values())
      .filter((r) => r.poolId === poolId && r.status === 'pending')
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((r) => ({ ...r }));
  }

  updatePsiRequestStatus(id: string, status: PendingPsiRequest['status']): void {
    const request = this.psiRequests.get(id);
    if (request) {
      request.status = status;
    }
  }

  // PSI Response operations

  insertPsiResponse(response: PsiResponseRecord): void {
    this.psiResponses.set(response.requestId, { ...response });
  }

  getPsiResponse(requestId: string): PsiResponseRecord | undefined {
    const response = this.psiResponses.get(requestId);
    return response ? { ...response } : undefined;
  }

  close(): void {
    this.pools.clear();
    this.participants.clear();
    this.preferences.clear();
    this.matchResults.clear();
    this.psiSetups.clear();
    this.psiRequests.clear();
    this.psiResponses.clear();
  }
}
