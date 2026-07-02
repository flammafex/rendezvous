/**
 * Rendezvous Web Server
 *
 * REST API for the Rendezvous matching system.
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuid } from 'uuid';
import {
  createRendezvous,
  Rendezvous,
  RendezvousError,
  PoolStatus,
  RendezvousConfig,
} from '../rendezvous/index.js';
import { HttpFreebirdAdapter } from '../rendezvous/adapters/freebird.js';
import { HttpWitnessAdapter } from '../rendezvous/adapters/witness.js';
import { FederationManager, FederationConfig, FederatedPoolMetadata, JoinRequestPayload } from '../federation/index.js';
import {
  decryptWithPrivateKey,
  deserializeEncryptedBox,
  hash,
  isValidPrivateKey,
  isValidPublicKey,
  isValidSignature,
  isValidSigningPublicKey,
  verifySignedRequest,
} from '../rendezvous/crypto.js';
import type { PrivateKey, PublicKey } from '../rendezvous/index.js';
import type { Signature, SigningPublicKey } from '../rendezvous/crypto.js';
import { getPsiService } from '../psi/index.js';
import type {
  PsiJoinRequest,
  PsiJoinResponse,
  OwnerHeldPsiSetup,
  PendingPsiRequest,
  PsiResponseRecord,
  OwnerPsiProcessingResult,
  PsiClientSession,
} from '../psi/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// PII redaction helper (M7)
// ============================================================================
//
// Logs throughout the server may include PII (displayName, publicKey,
// nullifier, bio, avatarUrl). This helper truncates such values so the log
// retains enough context to debug (first/last 4 chars) without exposing the
// full value. Pool IDs, counts, timestamps, status codes, and error messages
// are NOT considered PII and are logged in full.
function redact(value: unknown): string {
  if (typeof value !== 'string') return String(value);
  if (value.length <= 8) return '***';
  return value.slice(0, 4) + '***' + value.slice(-4);
}

// Configuration from environment variables
const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.RENDEZVOUS_DATA_DIR || './data';
const DB_PATH = path.join(DATA_DIR, 'rendezvous.db');

// External service configuration
// Freebird service URL - for invite code validation
const FREEBIRD_VERIFIER_URL = process.env.FREEBIRD_VERIFIER_URL;
// Witness gateway (default port 8080) - for timestamp attestation
const WITNESS_GATEWAY_URL = process.env.WITNESS_GATEWAY_URL;

// CORS configuration - comma-separated list of allowed origins.
// When unset, CORS is disabled (same-origin only).
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS;


// Ensure data directory exists
import fs from 'fs';
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Build Rendezvous configuration with optional adapters
const config: RendezvousConfig = {
  dbPath: DB_PATH,
};

// Configure Freebird adapter if service URL is provided
let freebirdAdapter: HttpFreebirdAdapter | null = null;
if (FREEBIRD_VERIFIER_URL) {
  console.log(`Freebird service: ${FREEBIRD_VERIFIER_URL}`);
  console.log('Pool creation requires invite code from Freebird');
  freebirdAdapter = new HttpFreebirdAdapter({
    verifierUrl: FREEBIRD_VERIFIER_URL,
  });
  config.freebird = freebirdAdapter;
} else {
  // Fail-closed default in production: without Freebird, pool creation is
  // open to the world. In dev/test, keep the warn-and-allow behavior.
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: FREEBIRD_VERIFIER_URL is not set. In production, pool creation would be open to anyone. Set FREEBIRD_VERIFIER_URL or run with NODE_ENV != production.');
    process.exit(1);
  }
  console.log('Freebird: not configured (set FREEBIRD_VERIFIER_URL to enable)');
  console.log('WARNING: Pool creation is open to anyone without Freebird configured');
}

// Configure Witness adapter if gateway URL is provided
if (WITNESS_GATEWAY_URL) {
  console.log(`Witness gateway: ${WITNESS_GATEWAY_URL}`);
  config.witness = new HttpWitnessAdapter({
    gatewayUrl: WITNESS_GATEWAY_URL,
  });
} else {
  console.log('Witness: not configured (set WITNESS_GATEWAY_URL to enable)');
}

// Initialize Rendezvous with configuration
const rv = createRendezvous(config);

// Track pools being processed (close + match computation) to avoid duplicate
// work between manual close, auto-close scheduler, and startup recovery.
const poolsBeingClosed = new Set<string>();

// ============================================================================
// Federation Configuration
// ============================================================================

const FEDERATION_ENABLED = process.env.FEDERATION_ENABLED === 'true';
const FEDERATION_PORT = parseInt(process.env.FEDERATION_PORT || '3001', 10);
const FEDERATION_INSTANCE_NAME = process.env.FEDERATION_INSTANCE_NAME || 'rendezvous-1';
const FEDERATION_PEERS = process.env.FEDERATION_PEERS?.split(',').filter(Boolean) || [];
// Publicly-reachable WebSocket endpoint for this instance, advertised to peers.
// When unset, falls back to ws://localhost:<port> which is unreachable from
// other hosts — only suitable for local development.
const FEDERATION_PUBLIC_ENDPOINT = process.env.FEDERATION_PUBLIC_ENDPOINT || '';
// Optional shared secret for authenticating incoming federation WebSocket
// connections. When unset, the manager accepts unauthenticated connections
// (dev mode) and logs a warning.
const FEDERATION_SHARED_SECRET = process.env.FEDERATION_SHARED_SECRET || '';

// Generate or load instance identity
const INSTANCE_ID = process.env.FEDERATION_INSTANCE_ID || uuid();
const INSTANCE_PUBLIC_KEY = process.env.FEDERATION_PUBLIC_KEY || '';
// Private key for decrypting incoming join requests (required for federation)
const INSTANCE_PRIVATE_KEY = process.env.FEDERATION_PRIVATE_KEY || '';

// Federation requires Freebird for anonymous messaging
const FREEBIRD_ISSUER_URL = process.env.FREEBIRD_ISSUER_URL || '';
// Use existing FREEBIRD_VERIFIER_URL or fall back to issuer URL for federation
const FEDERATION_VERIFIER_URL = FREEBIRD_VERIFIER_URL || FREEBIRD_ISSUER_URL;

// Config is built lazily after validation (freebirdIssuerUrl is required)
function buildFederationConfig(): FederationConfig {
  return {
    enabled: FEDERATION_ENABLED,
    instance: {
      id: INSTANCE_ID,
      name: FEDERATION_INSTANCE_NAME,
      endpoint: FEDERATION_PUBLIC_ENDPOINT || `ws://localhost:${FEDERATION_PORT}`,
      publicKey: INSTANCE_PUBLIC_KEY,
    },
    peers: FEDERATION_PEERS,
    syncInterval: 30000,
    freebirdIssuerUrl: FREEBIRD_ISSUER_URL,
    freebirdVerifierUrl: FEDERATION_VERIFIER_URL || undefined,
    sharedSecret: FEDERATION_SHARED_SECRET || undefined,
  };
}

// Initialize Federation Manager
let federation: FederationManager | null = null;
if (FEDERATION_ENABLED) {
  if (!FREEBIRD_ISSUER_URL) {
    console.error('Federation requires FREEBIRD_ISSUER_URL - all federation messages use anonymous tokens');
    process.exit(1);
  }
  console.log(`Federation: enabled as "${FEDERATION_INSTANCE_NAME}" (${INSTANCE_ID})`);
  console.log(`Federation peers: ${FEDERATION_PEERS.length > 0 ? FEDERATION_PEERS.join(', ') : 'none'}`);
  console.log(`Freebird: ${FREEBIRD_ISSUER_URL}`);
  if (!FEDERATION_PUBLIC_ENDPOINT) {
    console.warn('WARNING: FEDERATION_PUBLIC_ENDPOINT is not set — advertising ws://localhost (unreachable from peers). Set FEDERATION_PUBLIC_ENDPOINT to a publicly reachable ws:// or wss:// URL.');
  } else if (FEDERATION_PUBLIC_ENDPOINT.startsWith('ws://') && process.env.NODE_ENV === 'production') {
    console.warn('WARNING: FEDERATION_PUBLIC_ENDPOINT uses plaintext ws:// in production. Use wss:// to protect federation traffic.');
  } else if (FEDERATION_PUBLIC_ENDPOINT.startsWith('wss://')) {
    console.log(`Federation public endpoint: ${FEDERATION_PUBLIC_ENDPOINT}`);
  }
  if (!FEDERATION_SHARED_SECRET) {
    console.warn('WARNING: FEDERATION_SHARED_SECRET is not set — federation WebSocket accepts unauthenticated connections (dev mode).');
  }
  federation = new FederationManager(buildFederationConfig());

  // Handle federated token relays (all use anonymous Freebird tokens)
  federation.on('tokens:relayed', (relay) => {
    console.log(`Received token relay for pool ${relay.poolId}`);
    try {
      rv.submitPreferences({
        poolId: relay.poolId,
        matchTokens: relay.matchTokens,
        nullifier: relay.nullifier,
      });
    } catch (err) {
      console.error('Failed to process token relay:', err);
    }
  });

  // Handle federated join requests (all use anonymous Freebird tokens + encrypted payloads)
  federation.on('join:request', async (request) => {
    console.log(`Received join request for pool ${request.poolId}`);
    try {
      if (!INSTANCE_PRIVATE_KEY) {
        console.error('Cannot process join request: FEDERATION_PRIVATE_KEY not configured');
        return;
      }
      if (!isValidPrivateKey(INSTANCE_PRIVATE_KEY)) {
        console.error('Cannot process join request: FEDERATION_PRIVATE_KEY is invalid');
        return;
      }
      if (!isValidPublicKey(request.publicKey)) {
        console.error('Cannot process join request: request public key is invalid');
        return;
      }

      const requestPublicKey = request.publicKey as PublicKey;

      let payload: JoinRequestPayload;
      try {
        const encryptedBox = deserializeEncryptedBox(request.encryptedPayload);
        const decrypted = decryptWithPrivateKey(encryptedBox, INSTANCE_PRIVATE_KEY as PrivateKey);
        payload = JSON.parse(decrypted) as JoinRequestPayload;
      } catch (decryptErr) {
        console.error('Failed to decrypt join request payload:', decryptErr);
        return;
      }

      const eligibility = await rv.checkEligibility(request.poolId, requestPublicKey);
      if (eligibility.eligible) {
        rv.registerParticipant({
          poolId: request.poolId,
          publicKey: requestPublicKey,
          displayName: payload.displayName,
          bio: payload.bio,
        });
        console.log(`Registered participant ${redact(payload.displayName)} (key ${redact(request.publicKey)}) in pool ${request.poolId}`);
      }
    } catch (err) {
      console.error('Failed to process join request:', err);
    }
  });
} else {
  console.log('Federation: disabled (set FEDERATION_ENABLED=true to enable)');
}

// Create Express app
const app = express();

// ============================================================================
// Process-level error handlers
// ============================================================================

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Middleware
// Security headers via helmet. The vanilla-JS PWA in public/ uses inline
// scripts and loads crypto/QR libraries from CDNs, so the default CSP would
// break the UI. This is a deliberate tradeoff: the UI is a trusted first-party
// PWA, and tightening further would require vendoring all CDN deps and
// refactoring inline handlers to use addEventListener with nonces/SRI.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',  // qrcode-generator, jsQR
        'https://esm.run',           // @noble/curves, @noble/hashes
      ],
      scriptSrcElem: [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',
        'https://esm.run',
      ],
      scriptSrcAttr: ["'unsafe-inline'"],  // inline onclick handlers
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      styleSrcElem: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
    },
  },
}));
app.use(cors({
  origin: ALLOWED_ORIGINS ? ALLOWED_ORIGINS.split(',').map(s => s.trim()) : false,
}));
if (ALLOWED_ORIGINS) {
  console.log(`CORS: restricted to ${ALLOWED_ORIGINS.split(',').map(s => s.trim()).join(', ')}`);
} else {
  console.log('CORS: disabled (set ALLOWED_ORIGINS to enable, comma-separated)');
}
app.use(express.json({ limit: '256kb' }));

// Privacy enhancement: Pad all JSON responses to fixed 8KB blocks
// This prevents response size analysis attacks
const RESPONSE_BLOCK_SIZE = 8192; // 8KB blocks
app.use((_req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body: unknown) => {
    const json = JSON.stringify(body);
    const targetSize = Math.max(RESPONSE_BLOCK_SIZE, Math.ceil(json.length / RESPONSE_BLOCK_SIZE) * RESPONSE_BLOCK_SIZE);
    // Add padding field with random data to reach target size
    const paddingNeeded = targetSize - json.length - ',"_p":""}'.length + 1;
    if (paddingNeeded > 0 && typeof body === 'object' && body !== null) {
      // For arrays, wrap in envelope to preserve array structure
      if (Array.isArray(body)) {
        const envelope = { data: body, _p: 'x'.repeat(paddingNeeded) };
        return originalJson(envelope);
      }
      const paddedBody = { ...body, _p: 'x'.repeat(paddingNeeded) };
      return originalJson(paddedBody);
    }
    return originalJson(body);
  };
  next();
});

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../../public')));

// ============================================================================
// Rate Limiters (route-level middleware)
// ============================================================================

const FIFTEEN_MINUTES = 15 * 60 * 1000;

// Pool creation: strict (10 per 15 min per IP)
const createPoolLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many pool creation requests, please try again later' },
});

// Preference submission: moderate (50 per 15 min per IP)
const submitLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many submission requests, please try again later' },
});

// PSI CPU-heavy endpoints: strict (20 per 15 min per IP)
const psiLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many PSI requests, please try again later' },
});

// PSI response polling: moderate (100 per 15 min per IP)
const psiPollLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many polling requests, please try again later' },
});

// Error handler type
interface ApiError extends Error {
  status?: number;
  code?: string;
}

// ============================================================================
// Input length validation (M2)
// ============================================================================
//
// Bounds user-supplied text fields to prevent abuse (storage bloat, log
// flooding, DoS via oversized payloads). Returns an error message string
// when the value is present but exceeds the max length, otherwise null.
// Non-string values pass through (type/format validation happens elsewhere).
function validateLength(value: unknown, max: number, field: string): string | null {
  if (typeof value === 'string' && value.length > max) {
    return `${field} too long (max ${max} chars)`;
  }
  return null;
}

// ============================================================================
// API Routes
// ============================================================================

// Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

// Service status - test connectivity to external services
app.get('/api/status', async (_req: Request, res: Response) => {
  const status: {
    freebird: string;
    witness: string;
    federation: string;
    freebirdUrl?: string;
    requiresInvite?: boolean;
    witnessUrl?: string;
    federationPeers?: number;
    instanceId?: string;
  } = {
    freebird: 'unconfigured',
    witness: 'unconfigured',
    federation: 'disabled',
  };

  // Test Freebird connectivity
  // When Freebird is configured, pool creation requires invite code
  // When disconnected, pool creation is blocked (fail closed)
  if (FREEBIRD_VERIFIER_URL) {
    status.freebirdUrl = FREEBIRD_VERIFIER_URL;
    status.requiresInvite = true;
    try {
      // Use verify endpoint with empty body - 400 is expected but proves reachability
      const response = await fetch(`${FREEBIRD_VERIFIER_URL}/v1/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
        signal: AbortSignal.timeout(3000),
      });
      // 400 = service is up (invalid request is expected)
      // 5xx = service error
      status.freebird = response.status < 500 ? 'connected' : `error:${response.status}`;
    } catch (e) {
      status.freebird = 'disconnected';
    }
  }

  // Test Witness connectivity
  if (WITNESS_GATEWAY_URL) {
    status.witnessUrl = WITNESS_GATEWAY_URL;
    try {
      const response = await fetch(`${WITNESS_GATEWAY_URL}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(3000),
      });
      status.witness = response.ok ? 'connected' : `error:${response.status}`;
    } catch (e) {
      status.witness = 'disconnected';
    }
  }

  // Federation status
  if (federation) {
    const peerCount = federation.getConnectedPeerCount();
    status.federation = peerCount > 0 ? 'connected' : 'enabled';
    status.federationPeers = peerCount;
    status.instanceId = INSTANCE_ID;
  }

  res.json(status);
});

// ----------------------------------------------------------------------------
// Pool Management
// ----------------------------------------------------------------------------

// Create a pool
// When Freebird is configured: requires valid invite code, fails closed if disconnected
// When Freebird is not configured: open access (development/testing mode)
app.post('/api/pools', createPoolLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, description, creatorPublicKey, creatorSigningKey, commitDeadline, revealDeadline, maxPreferencesPerParticipant, ephemeral, requiresInviteToJoin, inviteCode } = req.body;

    if (!name || !creatorPublicKey || !creatorSigningKey || !revealDeadline) {
      res.status(400).json({ error: 'Missing required fields: name, creatorPublicKey, creatorSigningKey, revealDeadline' });
      return;
    }
    if (!isValidPublicKey(creatorPublicKey)) {
      res.status(400).json({ error: 'Invalid creatorPublicKey' });
      return;
    }

    // Field length validation (M2)
    const lengthError =
      validateLength(name, 200, 'name') ||
      validateLength(description, 2000, 'description');
    if (lengthError) {
      res.status(400).json({ error: lengthError });
      return;
    }

    // When Freebird is configured, require invite code and verify connectivity
    if (FREEBIRD_VERIFIER_URL) {
      // First check if Freebird is reachable (fail closed)
      // Use the verify endpoint with empty body - it will return 400 but proves service is up
      try {
        const healthResponse = await fetch(`${FREEBIRD_VERIFIER_URL}/v1/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
          signal: AbortSignal.timeout(3000),
        });
        // 400 is expected (invalid request), but proves service is reachable
        // 5xx would indicate service error
        if (healthResponse.status >= 500) {
          res.status(503).json({
            error: 'Pool creation unavailable: Freebird service error',
            freebirdStatus: 'error',
          });
          return;
        }
      } catch (e) {
        res.status(503).json({
          error: 'Pool creation unavailable: Freebird service is disconnected',
          freebirdStatus: 'disconnected',
        });
        return;
      }

      // Freebird is connected, require invite code
      if (!inviteCode || typeof inviteCode !== 'string' || !inviteCode.trim()) {
        res.status(403).json({
          error: 'Invite code required to create pools',
          requiresInvite: true,
        });
        return;
      }

      // Verify the invite code with Freebird
      if (freebirdAdapter) {
        const isValid = await freebirdAdapter.verifyInviteCode(inviteCode.trim());
        if (!isValid) {
          res.status(403).json({
            error: 'Invalid or already used invite code',
            requiresInvite: true,
          });
          return;
        }
      }
    }
    // If Freebird is not configured, allow open access (with warning logged at startup)

    const pool = rv.createPool({
      name,
      description,
      creatorPublicKey: creatorPublicKey as PublicKey,
      creatorSigningKey,
      commitDeadline: commitDeadline ? new Date(commitDeadline) : undefined,
      revealDeadline: new Date(revealDeadline),
      maxPreferencesPerParticipant,
      ephemeral: ephemeral === true,
      requiresInviteToJoin: requiresInviteToJoin === true,
    });

    res.status(201).json(pool);
  } catch (error) {
    next(error);
  }
});

// List pools
app.get('/api/pools', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { status, limit, offset } = req.query;

    const pools = rv.listPools({
      status: status as PoolStatus | undefined,
      limit: limit ? parseInt(limit as string, 10) : undefined,
      offset: offset ? parseInt(offset as string, 10) : undefined,
    });

    // Add phase info to each pool
    const poolsWithPhase = pools.map(pool => {
      const phase = rv.getPoolPhase(pool.id);
      return {
        ...pool,
        phase: {
          currentPhase: phase.currentPhase,
          nextPhase: phase.nextPhase,
          deadline: phase.deadline,
          remainingMs: phase.remainingMs,
        },
      };
    });

    res.json(poolsWithPhase);
  } catch (error) {
    next(error);
  }
});

// Get a pool
app.get('/api/pools/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = rv.getPool(req.params.id);

    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    const phase = rv.getPoolPhase(pool.id);
    const result = rv.getMatchResult(pool.id);

    res.json({
      ...pool,
      phase: {
        currentPhase: phase.currentPhase,
        nextPhase: phase.nextPhase,
        deadline: phase.deadline,
        remainingMs: phase.remainingMs,
      },
      matchResult: result || null,
    });
  } catch (error) {
    next(error);
  }
});

// Close a pool (owner-only)
// Privacy enhancement: Add random delay before match computation
// This makes it harder to correlate submission timing with results
app.post('/api/pools/:id/close', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { ownerPublicKey, signature, timestamp } = req.body;

    // Get pool first to verify ownership
    const poolToClose = rv.getPool(req.params.id);
    if (!poolToClose) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Dedup against in-flight auto-close / recovery processing (M3)
    if (poolsBeingClosed.has(poolToClose.id)) {
      res.status(409).json({ error: 'Pool close already in progress' });
      return;
    }

    // Verify owner signature
    const authError = verifyOwnerSignature(
      poolToClose,
      'pool-close',
      req.params.id,
      ownerPublicKey,
      signature,
      timestamp
    );
    if (authError) {
      res.status(403).json({ error: authError });
      return;
    }

    // Now close the pool
    const pool = rv.closePool(req.params.id);

    // Privacy enhancement: Random delay (30s to 3min) before match computation
    // This prevents timing analysis attacks
    const minDelay = 30_000;  // 30 seconds
    const maxDelay = 180_000; // 3 minutes
    const randomDelay = minDelay + Math.floor(Math.random() * (maxDelay - minDelay));

    console.log(`Pool ${pool.id} closed. Computing matches in ${Math.round(randomDelay / 1000)}s (privacy delay)`);

    // Return immediately with pending status
    res.json({
      pool,
      matchResult: null,
      status: 'computing',
      message: `Matches will be available shortly (privacy delay: ~${Math.round(randomDelay / 1000)}s)`,
    });

    // Compute matches after delay
    setTimeout(() => {
      (async () => {
        try {
          const result = await rv.detectMatches(pool.id);
          console.log(`Pool ${pool.id} match computation complete: ${result.matchedTokens.length} matches`);

          // Ephemeral cleanup: delete participant profiles after match detection
          if (pool.ephemeral) {
            const deleted = rv.deletePoolParticipants(pool.id);
            console.log(`Pool ${pool.id} ephemeral cleanup: deleted ${deleted} participant profiles`);
          }
        } catch (err) {
          console.error(`Failed to compute matches for pool ${pool.id}:`, err);
        }
      })();
    }, randomDelay);
  } catch (error) {
    next(error);
  }
});

// Get pool stats
app.get('/api/pools/:id/stats', (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    const result = rv.getMatchResult(req.params.id);
    if (!result) {
      res.status(400).json({ error: 'Pool must be closed first' });
      return;
    }

    const stats = rv.getMatchStats(req.params.id);
    res.json(stats);
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// Participant Registration
// ----------------------------------------------------------------------------

// Register as a participant
app.post('/api/pools/:id/participants', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { publicKey, displayName, bio, avatarUrl, profileData, eligibilityProof } = req.body;

    if (!publicKey || !displayName) {
      res.status(400).json({ error: 'Missing required fields: publicKey, displayName' });
      return;
    }
    if (!isValidPublicKey(publicKey)) {
      res.status(400).json({ error: 'Invalid publicKey' });
      return;
    }

    // Field length validation (M2)
    const lengthError =
      validateLength(displayName, 100, 'displayName') ||
      validateLength(bio, 5000, 'bio') ||
      validateLength(avatarUrl, 2000, 'avatarUrl');
    if (lengthError) {
      res.status(400).json({ error: lengthError });
      return;
    }

    const parsedPublicKey = publicKey as PublicKey;

    // Check eligibility before registration
    const eligibility = await rv.checkEligibility(req.params.id, parsedPublicKey);
    if (!eligibility.eligible) {
      res.status(403).json({
        error: 'Not eligible to join this pool',
        reason: eligibility.reason,
      });
      return;
    }

    const participant = rv.registerParticipant({
      poolId: req.params.id,
      publicKey: parsedPublicKey,
      displayName,
      bio,
      avatarUrl,
      profileData,
    });

    res.status(201).json(participant);
  } catch (error) {
    next(error);
  }
});

// List participants in a pool
app.get('/api/pools/:id/participants', (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    const { limit, offset } = req.query;
    const participants = rv.listParticipants(req.params.id, {
      limit: limit ? parseInt(limit as string, 10) : undefined,
      offset: offset ? parseInt(offset as string, 10) : undefined,
    });

    res.json({
      participants,
      total: rv.getParticipantCount(req.params.id),
    });
  } catch (error) {
    next(error);
  }
});

// Get a specific participant
app.get('/api/pools/:id/participants/:participantId', (req: Request, res: Response, next: NextFunction) => {
  try {
    const participant = rv.getParticipant(req.params.participantId);

    if (!participant || participant.poolId !== req.params.id) {
      res.status(404).json({ error: 'Participant not found' });
      return;
    }

    res.json(participant);
  } catch (error) {
    next(error);
  }
});

// Get my registration in a pool
app.get('/api/pools/:id/participants/by-key/:publicKey', (req: Request, res: Response, next: NextFunction) => {
  try {
    const participant = rv.getParticipantByPublicKey(req.params.id, req.params.publicKey);

    if (!participant) {
      res.status(404).json({ error: 'Not registered in this pool' });
      return;
    }

    res.json(participant);
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// Preference Submission
// ----------------------------------------------------------------------------

// Submit preferences
// When pool requires invite to join and Freebird is configured, verify invite code
app.post('/api/pools/:id/submit', submitLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { matchTokens, commitHashes, nullifier, revealData, inviteCode } = req.body;

    if (!matchTokens || !nullifier) {
      res.status(400).json({ error: 'Missing required fields: matchTokens, nullifier' });
      return;
    }

    // Server-side cap on matchTokens, independent of the pool's
    // maxPreferencesPerParticipant setting, to bound resource use when the
    // pool-level cap is unset.
    if (Array.isArray(matchTokens) && matchTokens.length > 1000) {
      res.status(400).json({ error: 'Too many match tokens (max 1000)' });
      return;
    }

    // Check if pool requires invite to join
    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    if (pool.requiresInviteToJoin && FREEBIRD_VERIFIER_URL) {
      // Fail closed: check Freebird connectivity first
      try {
        const healthResponse = await fetch(`${FREEBIRD_VERIFIER_URL}/v1/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
          signal: AbortSignal.timeout(3000),
        });
        if (healthResponse.status >= 500) {
          res.status(503).json({
            error: 'Pool submission unavailable: authorization service error',
            freebirdStatus: 'error',
          });
          return;
        }
      } catch (e) {
        res.status(503).json({
          error: 'Pool submission unavailable: authorization service is disconnected',
          freebirdStatus: 'disconnected',
        });
        return;
      }

      // Require and verify invite code
      if (!inviteCode || typeof inviteCode !== 'string' || !inviteCode.trim()) {
        res.status(403).json({
          error: 'Invite code required to join this pool',
          requiresInvite: true,
        });
        return;
      }

      if (freebirdAdapter) {
        const isValid = await freebirdAdapter.verifyInviteCode(inviteCode.trim());
        if (!isValid) {
          res.status(403).json({
            error: 'Invalid or already used invite code',
            requiresInvite: true,
          });
          return;
        }
      }
    }

    const result = rv.submitPreferences({
      poolId: req.params.id,
      matchTokens,
      commitHashes,
      nullifier,
      revealData,
    });

    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
});

// Reveal preferences
app.post('/api/pools/:id/reveal', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { matchTokens, nullifier } = req.body;

    if (!matchTokens || !nullifier) {
      res.status(400).json({ error: 'Missing required fields: matchTokens, nullifier' });
      return;
    }

    const result = rv.revealPreferences({
      poolId: req.params.id,
      matchTokens,
      nullifier,
    });

    res.json(result);
  } catch (error) {
    next(error);
  }
});

// Get match results (legacy compatibility endpoint used by web UI discover flow)
app.get('/api/pools/:id/matches', (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Match computation only occurs once the pool is closed
    if (pool.status !== 'closed') {
      res.status(400).json({ error: 'Pool must be closed before querying matches' });
      return;
    }

    const result = rv.getMatchResult(req.params.id);
    if (!result) {
      res.status(400).json({ error: 'Pool may not be closed yet. Matches are being computed.' });
      return;
    }

    res.json(result);
  } catch (error) {
    next(error);
  }
});

// Check if submitted
app.get('/api/pools/:id/submitted/:nullifier', (req: Request, res: Response, next: NextFunction) => {
  try {
    const hasSubmitted = rv.hasSubmitted(req.params.id, req.params.nullifier);
    res.json({ submitted: hasSubmitted });
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// Match Results (PSI-based - owner-held key)
// ----------------------------------------------------------------------------

// Query matches using PSI (privacy-preserving)
// Requests are queued for pool owner to process
app.post('/api/pools/:id/query-matches', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { psiRequest, authToken } = req.body;

    if (!psiRequest) {
      res.status(400).json({ error: 'psiRequest required (create with /api/psi/create-request)' });
      return;
    }

    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    if (pool.status !== 'closed') {
      res.status(400).json({ error: 'Pool not closed yet' });
      return;
    }

    const ownerSetup = rv.store.getPsiSetup(req.params.id);
    if (!ownerSetup) {
      res.status(400).json({ error: 'PSI setup not created. Pool owner must create setup first.' });
      return;
    }

    const requestId = uuid();
    const request: PendingPsiRequest = {
      id: requestId,
      poolId: req.params.id,
      psiRequest,
      status: 'pending',
      createdAt: Date.now(),
      authTokenHash: authToken ? hash(authToken) : undefined,
    };

    rv.store.insertPsiRequest(request);

    res.status(202).json({
      requestId,
      status: 'pending',
      message: 'Request queued for pool owner processing. Poll for result.',
      pollUrl: `/api/psi/response/${requestId}`,
    });
  } catch (error) {
    next(error);
  }
});

// Get reveal data for matched tokens
// Returns encrypted contact info for each matched token (decryptable only by matching parties)
app.get('/api/pools/:id/matches/reveal-data', (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = rv.getMatchResult(req.params.id);

    if (!result) {
      res.status(404).json({ error: 'No match results available. Pool may not be closed.' });
      return;
    }

    // Get all preferences for this pool and build a map of
    // matchToken -> encryptedReveal[] (one entry per matched participant)
    const preferences = rv.getPreferencesByPool(req.params.id);
    const revealDataMap: Record<string, string[]> = {};

    for (const token of result.matchedTokens) {
      // Find preferences with this token and get their encrypted reveal data
      const matchingPrefs = preferences.filter(p => p.matchToken === token && p.encryptedReveal);
      const encryptedEntries = matchingPrefs
        .map(pref => pref.encryptedReveal)
        .filter((entry): entry is string => Boolean(entry));

      if (encryptedEntries.length > 0) {
        revealDataMap[token] = encryptedEntries;
      }
    }

    res.json({
      matchedTokens: result.matchedTokens,
      revealData: revealDataMap,
    });
  } catch (error) {
    next(error);
  }
});

// Deprecated legacy reveal-data format (kept for compatibility if needed by older clients)
app.get('/api/pools/:id/matches/reveal-data-legacy', (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = rv.getMatchResult(req.params.id);

    if (!result) {
      res.status(404).json({ error: 'No match results available. Pool may not be closed.' });
      return;
    }

    const preferences = rv.getPreferencesByPool(req.params.id);
    const revealDataMap: Record<string, string | null> = {};

    for (const token of result.matchedTokens) {
      const matchingPrefs = preferences.filter(p => p.matchToken === token && p.encryptedReveal);
      // There could be up to 2 preferences with this token (one from each party)
      for (const pref of matchingPrefs) {
        if (pref.encryptedReveal) {
          // Store with a key that combines token + some identifier
          // Since both parties have the same token, we store both reveal data entries
          if (!revealDataMap[token]) {
            revealDataMap[token] = pref.encryptedReveal;
          } else {
            // Store second entry with a suffix
            revealDataMap[token + ':other'] = pref.encryptedReveal;
          }
        }
      }
    }

    res.json({
      matchedTokens: result.matchedTokens,
      revealData: revealDataMap,
    });
  } catch (error) {
    next(error);
  }
});

// Verify match integrity
app.get('/api/pools/:id/verify', (req: Request, res: Response, next: NextFunction) => {
  try {
    const verification = rv.verifyMatchIntegrity(req.params.id);
    res.json(verification);
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// PSI (Private Set Intersection) Client Helpers
// ----------------------------------------------------------------------------

function parsePsiClientSession(
  session: unknown,
  legacyClientKey: unknown,
  legacyInputs: unknown,
): PsiClientSession | undefined {
  if (
    session &&
    typeof session === 'object' &&
    typeof (session as { clientKey?: unknown }).clientKey === 'string' &&
    Array.isArray((session as { inputs?: unknown }).inputs)
  ) {
    const inputs = (session as { inputs: unknown[] }).inputs;
    if (inputs.every((input) => typeof input === 'string')) {
      return {
        clientKey: (session as { clientKey: string }).clientKey,
        inputs: inputs as string[],
      };
    }
  }

  if (
    typeof legacyClientKey === 'string' &&
    Array.isArray(legacyInputs) &&
    legacyInputs.every((input) => typeof input === 'string')
  ) {
    return {
      clientKey: legacyClientKey,
      inputs: legacyInputs as string[],
    };
  }

  return undefined;
}

// Client-side helper: Create PSI request
// (This could also be done entirely client-side with the WASM library)
app.post('/api/psi/create-request', psiLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { inputs } = req.body;

    if (!inputs || !Array.isArray(inputs)) {
      res.status(400).json({ error: 'inputs array required' });
      return;
    }

    const psiService = getPsiService();
    const result = await psiService.createRequest(inputs);

    res.json({
      psiRequest: result.request,
      session: result.session,
      message: 'Send psiRequest to server. Keep session to compute intersection.',
    });
  } catch (error) {
    next(error);
  }
});

// Client-side helper: Compute intersection
// (This could also be done entirely client-side with the WASM library)
app.post('/api/psi/compute-intersection', psiLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { session, clientKey, inputs, psiSetup, psiResponse } = req.body;
    const clientSession = parsePsiClientSession(session, clientKey, inputs);

    if (!clientSession || !psiSetup || !psiResponse) {
      res.status(400).json({ error: 'session, psiSetup, and psiResponse required' });
      return;
    }

    const psiService = getPsiService();
    const result = await psiService.computeIntersection(
      clientSession,
      psiSetup,
      psiResponse
    );

    res.json(result);
  } catch (error) {
    next(error);
  }
});

// Client-side helper: Compute cardinality only (more private - reveals count, not identities)
// (This could also be done entirely client-side with the WASM library)
app.post('/api/psi/compute-cardinality', psiLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { session, clientKey, inputs, psiSetup, psiResponse } = req.body;
    const clientSession = parsePsiClientSession(session, clientKey, inputs);

    if (!clientSession || !psiSetup || !psiResponse) {
      res.status(400).json({ error: 'session, psiSetup, and psiResponse required' });
      return;
    }

    const psiService = getPsiService();
    const cardinality = await psiService.computeCardinality(
      clientSession,
      psiSetup,
      psiResponse
    );

    res.json({ cardinality });
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// PSI Owner-Held Key Endpoints (Option B - Pool Owner Holds Key)
// ----------------------------------------------------------------------------

// ============================================================================
// Owner signature replay cache (H1)
// ============================================================================
//
// verifySignedRequest (re-exported from matchlock) enforces a 5-minute
// timestamp window but has no nonce or replay cache, so a captured valid
// signature could be replayed within that window. We hash the signature
// string and track recently-seen hashes with a TTL matching the 5-min window.
// Entries are pruned on each check to bound memory growth.

const SIGNATURE_REPLAY_TTL_MS = 5 * 60 * 1000; // matches verifySignedRequest window
const signatureReplayCache = new Map<string, number>(); // hash -> expiresAt (ms epoch)

function pruneExpiredReplayEntries(): void {
  const now = Date.now();
  for (const [sigHash, expiresAt] of signatureReplayCache) {
    if (expiresAt <= now) {
      signatureReplayCache.delete(sigHash);
    }
  }
}

/**
 * Returns true if the signature hash was already seen (replay), false otherwise.
 * Records the hash on first sight.
 */
function isReplayedSignature(signature: string): boolean {
  pruneExpiredReplayEntries();
  const sigHash = hash(signature);
  if (signatureReplayCache.has(sigHash)) {
    return true;
  }
  signatureReplayCache.set(sigHash, Date.now() + SIGNATURE_REPLAY_TTL_MS);
  return false;
}

/**
 * Verify owner signature for authenticated endpoints.
 * Returns error message if verification fails, undefined if successful.
 */
function verifyOwnerSignature(
  pool: { creatorPublicKey: string; creatorSigningKey: string },
  action: string,
  poolId: string,
  ownerPublicKey: string,
  signature?: string,
  timestamp?: number
): string | undefined {
  if (pool.creatorPublicKey !== ownerPublicKey) {
    return 'Only pool owner can perform this action';
  }

  if (!signature || !timestamp) {
    return 'Signature and timestamp required';
  }

  if (!isValidSignature(signature)) {
    return 'Invalid signature format';
  }

  if (!isValidSigningPublicKey(pool.creatorSigningKey)) {
    return 'Invalid owner signing key';
  }

  if (!verifySignedRequest(
    action,
    poolId,
    signature as Signature,
    timestamp,
    pool.creatorSigningKey as SigningPublicKey,
  )) {
    return 'Invalid or expired signature';
  }

  // Replay protection: after the signature verifies, ensure it has not been
  // used before within the 5-minute window.
  if (isReplayedSignature(signature)) {
    console.error(`Signature replay detected for action "${action}" on pool ${poolId}`);
    return 'Replay detected';
  }

  return undefined;
}


/**
 * Pool owner submits encrypted PSI setup.
 * The server stores this but CANNOT decrypt the server key.
 */
app.post('/api/pools/:id/psi/owner-setup', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { setupMessage, encryptedServerKey, ownerPublicKey, signature, timestamp, fpr, maxClientElements, dataStructure } = req.body;

    if (!setupMessage || !encryptedServerKey || !ownerPublicKey) {
      res.status(400).json({ error: 'setupMessage, encryptedServerKey, and ownerPublicKey are required' });
      return;
    }

    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Verify owner with signature if pool has signing key
    const authError = verifyOwnerSignature(pool, 'psi-owner-setup', req.params.id, ownerPublicKey, signature, timestamp);
    if (authError) {
      res.status(403).json({ error: authError });
      return;
    }

    // Check if setup already exists
    const existingSetup = rv.store.getPsiSetup(req.params.id);
    if (existingSetup) {
      res.status(409).json({ error: 'PSI setup already exists for this pool' });
      return;
    }

    const setup: OwnerHeldPsiSetup = {
      poolId: req.params.id,
      setupMessage,
      encryptedServerKey,
      ownerPublicKey,
      fpr: fpr ?? 0.001,
      maxClientElements: maxClientElements ?? 10000,
      dataStructure: dataStructure ?? 'GCS',
      createdAt: Date.now(),
    };

    rv.store.insertPsiSetup(setup);

    res.status(201).json({
      message: 'PSI setup created successfully',
      poolId: setup.poolId,
      fpr: setup.fpr,
      maxClientElements: setup.maxClientElements,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Get PSI setup status (public info only, no encrypted key).
 */
app.get('/api/pools/:id/psi/status', (req: Request, res: Response, next: NextFunction) => {
  try {
    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    const setup = rv.store.getPsiSetup(req.params.id);
    if (!setup) {
      res.json({
        hasSetup: false,
        message: 'Pool owner has not created PSI setup yet',
      });
      return;
    }

    res.json({
      hasSetup: true,
      poolId: setup.poolId,
      fpr: setup.fpr,
      maxClientElements: setup.maxClientElements,
      dataStructure: setup.dataStructure,
      createdAt: setup.createdAt,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Client submits PSI request (queued for owner processing).
 * Returns a request ID that the client can poll for response.
 */
app.post('/api/pools/:id/psi/request', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { psiRequest, authToken } = req.body;

    if (!psiRequest) {
      res.status(400).json({ error: 'psiRequest is required' });
      return;
    }

    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Pool must be closed
    if (pool.status !== 'closed') {
      res.status(400).json({ error: 'Pool must be closed before querying matches' });
      return;
    }

    // PSI setup must exist
    const setup = rv.store.getPsiSetup(req.params.id);
    if (!setup) {
      res.status(400).json({ error: 'PSI setup not created. Pool owner must create setup first.' });
      return;
    }

    const requestId = uuid();
    const request: PendingPsiRequest = {
      id: requestId,
      poolId: req.params.id,
      psiRequest,
      status: 'pending',
      createdAt: Date.now(),
      authTokenHash: authToken ? hash(authToken) : undefined,
    };

    rv.store.insertPsiRequest(request);

    res.status(202).json({
      requestId,
      status: 'pending',
      message: 'Request queued. Poll GET /api/psi/response/:requestId for result.',
      pollUrl: `/api/psi/response/${requestId}`,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Pool owner polls for pending PSI requests.
 * Requires signature verification when pool has signing key.
 */
app.get('/api/pools/:id/psi/pending', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { ownerPublicKey, signature, timestamp } = req.query;

    if (!ownerPublicKey || typeof ownerPublicKey !== 'string') {
      res.status(400).json({ error: 'ownerPublicKey query parameter is required' });
      return;
    }

    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Verify owner with signature if pool has signing key
    const authError = verifyOwnerSignature(
      pool,
      'psi-pending',
      req.params.id,
      ownerPublicKey,
      typeof signature === 'string' ? signature : undefined,
      typeof timestamp === 'string' ? parseInt(timestamp, 10) : undefined
    );
    if (authError) {
      res.status(403).json({ error: authError });
      return;
    }

    const setup = rv.store.getPsiSetup(req.params.id);
    if (!setup) {
      res.status(400).json({ error: 'PSI setup not created yet' });
      return;
    }

    const pendingRequests = rv.store.getPendingPsiRequestsByPool(req.params.id);

    res.json({
      poolId: req.params.id,
      pendingCount: pendingRequests.length,
      requests: pendingRequests,
      psiSetup: {
        setupMessage: setup.setupMessage,
        encryptedServerKey: setup.encryptedServerKey,
        fpr: setup.fpr,
        maxClientElements: setup.maxClientElements,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Pool owner submits processed PSI responses.
 * Requires signature verification when pool has signing key.
 */
app.post('/api/pools/:id/psi/responses', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { responses, ownerPublicKey, signature, timestamp } = req.body as {
      responses: OwnerPsiProcessingResult[];
      ownerPublicKey: string;
      signature?: string;
      timestamp?: number;
    };

    if (!responses || !Array.isArray(responses) || !ownerPublicKey) {
      res.status(400).json({ error: 'responses array and ownerPublicKey are required' });
      return;
    }

    const pool = rv.getPool(req.params.id);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Verify owner with signature if pool has signing key
    const authError = verifyOwnerSignature(pool, 'psi-responses', req.params.id, ownerPublicKey, signature, timestamp);
    if (authError) {
      res.status(403).json({ error: authError });
      return;
    }

    const setup = rv.store.getPsiSetup(req.params.id);
    if (!setup) {
      res.status(400).json({ error: 'PSI setup not found' });
      return;
    }

    const processed: string[] = [];
    const errors: string[] = [];
    const now = Date.now();
    const expiresAt = now + 60 * 60 * 1000; // 1 hour expiration

    for (const result of responses) {
      const request = rv.store.getPsiRequest(result.requestId);
      if (!request) {
        errors.push(`Request ${result.requestId} not found`);
        continue;
      }
      if (request.poolId !== req.params.id) {
        errors.push(`Request ${result.requestId} belongs to different pool`);
        continue;
      }
      if (request.status !== 'pending') {
        errors.push(`Request ${result.requestId} is not pending (status: ${request.status})`);
        continue;
      }

      const response: PsiResponseRecord = {
        id: uuid(),
        requestId: result.requestId,
        poolId: req.params.id,
        psiSetup: setup.setupMessage,
        psiResponse: result.psiResponse,
        createdAt: now,
        expiresAt,
      };

      rv.store.insertPsiResponse(response);
      rv.store.updatePsiRequestStatus(result.requestId, 'completed');
      processed.push(result.requestId);
    }

    res.json({
      processed: processed.length,
      processedIds: processed,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Client polls for their PSI response.
 * Requires the auth token presented at request-creation time (matched via
 * authTokenHash). Accept the token via the `?token=` query parameter or the
 * `X-PSI-Auth-Token` header. If the request was created without an auth
 * token, no token is required to poll.
 */
app.get('/api/psi/response/:requestId', psiPollLimiter, (req: Request, res: Response, next: NextFunction) => {
  try {
    const request = rv.store.getPsiRequest(req.params.requestId);
    if (!request) {
      res.status(404).json({ error: 'Request not found' });
      return;
    }

    // Auth token check: if the request was created with an authTokenHash,
    // the caller must present the matching token.
    if (request.authTokenHash) {
      const presentedToken =
        (typeof req.query.token === 'string' && req.query.token) ||
        (typeof req.headers['x-psi-auth-token'] === 'string' && req.headers['x-psi-auth-token']);
      if (!presentedToken) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }
      if (hash(presentedToken) !== request.authTokenHash) {
        res.status(403).json({ error: 'Invalid auth token' });
        return;
      }
    }

    if (request.status === 'pending') {
      res.json({
        requestId: req.params.requestId,
        status: 'pending',
        message: 'Request is still being processed by pool owner',
      });
      return;
    }

    if (request.status === 'expired') {
      res.status(410).json({
        requestId: req.params.requestId,
        status: 'expired',
        error: 'Request expired before owner could process it',
      });
      return;
    }

    const response = rv.store.getPsiResponse(req.params.requestId);
    if (!response) {
      res.status(500).json({
        error: 'Request marked completed but response not found',
      });
      return;
    }

    // Check if response has expired
    if (Date.now() > response.expiresAt) {
      res.status(410).json({
        requestId: req.params.requestId,
        status: 'expired',
        error: 'Response has expired',
      });
      return;
    }

    res.json({
      requestId: req.params.requestId,
      status: 'completed',
      psiSetup: response.psiSetup,
      psiResponse: response.psiResponse,
      message: 'Use /api/psi/compute-intersection to find your matches locally',
    });
  } catch (error) {
    next(error);
  }
});

// ----------------------------------------------------------------------------
// Federation API
// ----------------------------------------------------------------------------

// Get federation status and info
app.get('/api/federation', (_req: Request, res: Response) => {
  if (!federation) {
    res.json({
      enabled: false,
      message: 'Federation is not enabled on this instance',
    });
    return;
  }

  res.json({
    enabled: true,
    instanceId: INSTANCE_ID,
    instanceName: FEDERATION_INSTANCE_NAME,
    connectedPeers: federation.getConnectedPeerCount(),
    knownInstances: federation.getInstances(),
    federatedPools: federation.getFederatedPools().length,
  });
});

// List federated pools (pools from other instances)
app.get('/api/federation/pools', (_req: Request, res: Response) => {
  if (!federation) {
    res.json({ pools: [] });
    return;
  }

  const pools = federation.getFederatedPools();
  res.json({ pools });
});

// Get a specific federated pool
app.get('/api/federation/pools/:id', (req: Request, res: Response) => {
  if (!federation) {
    res.status(404).json({ error: 'Federation not enabled' });
    return;
  }

  const pool = federation.getFederatedPool(req.params.id);
  if (!pool) {
    res.status(404).json({ error: 'Federated pool not found' });
    return;
  }

  res.json(pool);
});

// Announce a local pool to the federation (owner-only)
app.post('/api/federation/announce/:poolId', (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!federation) {
      res.status(400).json({ error: 'Federation not enabled' });
      return;
    }

    const { ownerPublicKey, signature, timestamp } = req.body;

    const pool = rv.getPool(req.params.poolId);
    if (!pool) {
      res.status(404).json({ error: 'Pool not found' });
      return;
    }

    // Verify owner signature
    const authError = verifyOwnerSignature(
      pool,
      'federation-announce',
      req.params.poolId,
      ownerPublicKey,
      signature,
      timestamp
    );
    if (authError) {
      res.status(403).json({ error: authError });
      return;
    }

    const phase = rv.getPoolPhase(pool.id);
    const metadata: FederatedPoolMetadata = {
      poolId: pool.id,
      ownerInstance: INSTANCE_ID,
      ownerPublicKey: INSTANCE_PUBLIC_KEY,
      name: pool.name,
      description: pool.description,
      revealDeadline: new Date(pool.revealDeadline).getTime(),
      phase: phase.currentPhase as 'open' | 'commit' | 'reveal' | 'closed',
      participantCount: rv.getParticipantCount(pool.id),
      gateType: pool.eligibilityGate?.type || 'open',
      updatedAt: Date.now(),
    };

    federation.announcePool(metadata);
    res.json({ announced: true, pool: metadata });
  } catch (error) {
    next(error);
  }
});

// Join a federated pool (cross-instance)
app.post('/api/federation/join/:poolId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!federation) {
      res.status(400).json({ error: 'Federation not enabled' });
      return;
    }

    const { publicKey, displayName, bio } = req.body;
    if (!publicKey || !displayName) {
      res.status(400).json({ error: 'Missing required fields: publicKey, displayName' });
      return;
    }

    const response = await federation.requestJoin(req.params.poolId, publicKey, displayName, bio);
    res.json(response);
  } catch (error) {
    next(error);
  }
});

// List known federation instances
app.get('/api/federation/instances', (_req: Request, res: Response) => {
  if (!federation) {
    res.json({ instances: [] });
    return;
  }

  res.json({ instances: federation.getInstances() });
});

// ----------------------------------------------------------------------------
// Error Handler
// ----------------------------------------------------------------------------

app.use((err: ApiError, _req: Request, res: Response, _next: NextFunction) => {
  // Always log the full error server-side for debugging.
  console.error('API Error:', err);

  // RendezvousError instances are user-facing 400s; their messages are safe
  // to return to clients. Generic errors (500s) must not leak internals.
  if (err instanceof RendezvousError) {
    res.status(400).json({
      error: err.message,
      code: err.code,
    });
    return;
  }

  res.status(err.status || 500).json({
    error: 'Internal server error',
  });
});

// ----------------------------------------------------------------------------
// Start Server
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Auto-Close Scheduler (Privacy Delay)
// ----------------------------------------------------------------------------

// Check for pools past reveal deadline and close them with privacy delay
async function checkAndCloseExpiredPools(): Promise<void> {
  // Periodic PSI data cleanup (M5). Runs alongside the auto-close scheduler
  // (every 60s). Wrapped in try/catch so a cleanup failure doesn't break
  // the scheduler's primary close/detect loop.
  try {
    const cleaned = rv.store.cleanupExpiredPsiData();
    if (cleaned.requests > 0 || cleaned.responses > 0) {
      console.log(`PSI cleanup: removed ${cleaned.requests} expired request(s), ${cleaned.responses} expired response(s)`);
    }
  } catch (err) {
    console.error('PSI cleanup failed:', err);
  }

  const pools = rv.listPools({ status: 'open' }).concat(rv.listPools({ status: 'reveal' }));
  const now = new Date();

  for (const pool of pools) {
    if (pool.revealDeadline <= now && !poolsBeingClosed.has(pool.id)) {
      poolsBeingClosed.add(pool.id);

      // Random delay (30s to 3min) before processing
      const minDelay = 30_000;
      const maxDelay = 180_000;
      const randomDelay = minDelay + Math.floor(Math.random() * (maxDelay - minDelay));

      console.log(`Pool ${pool.id} past deadline. Auto-closing with ${Math.round(randomDelay / 1000)}s privacy delay`);

      setTimeout(() => {
        (async () => {
          try {
            rv.closePool(pool.id);
            const result = await rv.detectMatches(pool.id);
            console.log(`Pool ${pool.id} auto-closed: ${result.matchedTokens.length} matches`);

            if (pool.ephemeral) {
              const deleted = rv.deletePoolParticipants(pool.id);
              console.log(`Pool ${pool.id} ephemeral cleanup: deleted ${deleted} profiles`);
            }
          } catch (err) {
            console.error(`Failed to auto-close pool ${pool.id}:`, err);
          } finally {
            poolsBeingClosed.delete(pool.id);
          }
        })();
      }, randomDelay);
    }
  }
}

// Run scheduler every minute
let autoCloseInterval: ReturnType<typeof setInterval>;
// HTTP server handle, stored so signal handlers can close it gracefully (M1).
let server: ReturnType<typeof app.listen>;

// ----------------------------------------------------------------------------
// Startup Recovery: re-enqueue match computation for stuck 'closed' pools
// ----------------------------------------------------------------------------

// Manual close flips status to 'closed' immediately, then schedules detectMatches
// 30s–3min later. If the process restarts in that window, the pool stays 'closed'
// forever with no match results. This recovery step re-enqueues those pools once
// at startup, mirroring the manual-close privacy-delay + detect + cleanup logic.
function recoverStuckClosedPools(): void {
  const stuckPools = rv.store.getClosedPoolsWithoutResults();
  if (stuckPools.length === 0) {
    return;
  }

  console.log(`Found ${stuckPools.length} stuck closed pool(s) without match results — re-enqueuing`);

  for (const pool of stuckPools) {
    // Dedup against in-flight scheduler processing
    if (poolsBeingClosed.has(pool.id)) {
      continue;
    }
    poolsBeingClosed.add(pool.id);
    console.log(`Recovering stuck closed pool ${pool.id}`);

    // Same privacy-delay range as manual close / auto-close (30s to 3min)
    const minDelay = 30_000;
    const maxDelay = 180_000;
    const randomDelay = minDelay + Math.floor(Math.random() * (maxDelay - minDelay));

    console.log(`Pool ${pool.id} recovery: computing matches in ${Math.round(randomDelay / 1000)}s (privacy delay)`);

    setTimeout(() => {
      (async () => {
        try {
          const result = await rv.detectMatches(pool.id);
          console.log(`Pool ${pool.id} recovery complete: ${result.matchedTokens.length} matches`);

          if (pool.ephemeral) {
            const deleted = rv.deletePoolParticipants(pool.id);
            console.log(`Pool ${pool.id} ephemeral cleanup: deleted ${deleted} participant profiles`);
          }
        } catch (err) {
          console.error(`Failed to recover matches for pool ${pool.id}:`, err);
        } finally {
          poolsBeingClosed.delete(pool.id);
        }
      })();
    }, randomDelay);
  }
}

server = app.listen(PORT, async () => {
  console.log(`Rendezvous server running at http://localhost:${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
  console.log(`Web UI available at http://localhost:${PORT}`);

  // Start auto-close scheduler
  autoCloseInterval = setInterval(checkAndCloseExpiredPools, 60_000);
  console.log('Auto-close scheduler started (checks every 60s)');

  // Recover any pools stuck in 'closed' state without match results
  recoverStuckClosedPools();

  // Start federation if enabled
  if (federation) {
    await federation.start(FEDERATION_PORT);
    console.log(`Federation WebSocket server on port ${FEDERATION_PORT}`);
  }
});

// Graceful shutdown (M1): stop accepting new connections, drain in-flight
// requests, then close the DB. Without server.close(), in-flight requests
// are killed abruptly and rv.close() can close the SQLite DB while a
// request is still using it.
async function gracefulShutdown(signal: string): Promise<void> {
  console.log(`\nShutting down gracefully (received ${signal})...`);
  clearInterval(autoCloseInterval);

  // Stop accepting new connections and drain keep-alive sockets.
  // closeAllConnections() (Node 18.2+) closes idle keep-alive connections;
  // server.close() waits for in-flight requests to finish.
  const httpServer = server;
  if (httpServer) {
    try {
      httpServer.closeAllConnections();
    } catch (err) {
      console.error('Error closing connections:', err);
    }
    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  }

  if (federation) {
    await federation.stop();
  }
  rv.close();
  process.exit(0);
}

process.on('SIGINT', () => {
  void gracefulShutdown('SIGINT');
});

process.on('SIGTERM', () => {
  void gracefulShutdown('SIGTERM');
});

export { app, rv };
