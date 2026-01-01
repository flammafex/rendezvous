/**
 * Federation Manager
 *
 * Manages federated state synchronization using Automerge CRDTs.
 * Based on HyperToken's ConsensusCore pattern for distributed sync.
 */

import * as Automerge from '@automerge/automerge';
import { WebSocket, WebSocketServer } from 'ws';
import { v4 as uuid } from 'uuid';
import { EventEmitter } from 'events';
import {
  FederationConfig,
  FederationState,
  FederatedPoolMetadata,
  FederationMessage,
  SyncMessage,
  PoolAnnounceMessage,
  JoinRequestPayload,
  JoinResponseMessage,
  ResultNotifyMessage,
  PeerState,
  InstanceId,
  AnonymousFederationMessage,
  AnonymousTokenRelayMessage,
  AnonymousJoinRequestMessage,
  isAnonymousMessage,
} from './types.js';
import {
  encryptForPublicKey,
  serializeEncryptedBox,
} from '../rendezvous/crypto.js';
import { FederationAuthProvider } from './freebird-client.js';

type SyncState = Automerge.SyncState;

/**
 * Events emitted by FederationManager
 * All join/relay events use anonymous message types (Freebird tokens, no instance IDs)
 */
export interface FederationEvents {
  'peer:connected': (instanceId: string) => void;
  'peer:disconnected': (instanceId: string) => void;
  'pool:announced': (pool: FederatedPoolMetadata) => void;
  'pool:updated': (pool: FederatedPoolMetadata) => void;
  'join:request': (request: AnonymousJoinRequestMessage) => void;
  'tokens:relayed': (relay: AnonymousTokenRelayMessage) => void;
  'results:received': (results: ResultNotifyMessage) => void;
  'state:changed': (state: FederationState) => void;
}

/**
 * FederationManager handles peer-to-peer synchronization of pool metadata
 * across federated Rendezvous instances using Automerge CRDTs.
 */
export class FederationManager extends EventEmitter {
  private config: FederationConfig;
  private doc: Automerge.Doc<FederationState>;
  private peers: Map<string, PeerState> = new Map();
  private peerSockets: Map<string, WebSocket> = new Map();
  private syncStates: Map<string, SyncState> = new Map();
  private pendingResponses: Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }> = new Map();
  private server?: WebSocketServer;
  private syncInterval?: ReturnType<typeof setInterval>;
  private running = false;
  private authProvider: FederationAuthProvider;

  constructor(config: FederationConfig) {
    super();
    this.config = config;

    // Initialize Automerge document with federation state
    this.doc = Automerge.from<FederationState>({
      instances: {
        [config.instance.id]: config.instance,
      },
      pools: {},
      version: 1,
    });

    // Freebird is required for federation - all messages use anonymous tokens
    this.authProvider = new FederationAuthProvider(
      config.freebirdIssuerUrl,
      config.freebirdVerifierUrl
    );
  }

  /**
   * Start the federation manager
   * - Starts WebSocket server for incoming connections
   * - Connects to known peers
   * - Begins sync interval
   */
  async start(port?: number): Promise<void> {
    if (!this.config.enabled) {
      console.log('Federation disabled');
      return;
    }

    this.running = true;

    // Start WebSocket server for incoming peer connections
    if (port) {
      this.server = new WebSocketServer({ port });
      this.server.on('connection', (ws, req) => {
        this.handleIncomingConnection(ws, req.url || '');
      });
      console.log(`Federation server listening on port ${port}`);
    }

    // Connect to known peers
    for (const peerEndpoint of this.config.peers) {
      this.connectToPeer(peerEndpoint);
    }

    // Start periodic sync
    const interval = this.config.syncInterval ?? 30000;
    this.syncInterval = setInterval(() => this.syncAllPeers(), interval);
  }

  /**
   * Stop the federation manager
   */
  async stop(): Promise<void> {
    this.running = false;

    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }

    // Close all peer connections
    for (const [, peer] of this.peers) {
      if (peer.connected) {
        // Connection will be closed when we stop
      }
    }
    this.peers.clear();
    this.syncStates.clear();

    // Close server
    if (this.server) {
      this.server.close();
    }
  }

  /**
   * Announce a pool to the federation
   */
  announcePool(pool: FederatedPoolMetadata): void {
    // Update local CRDT state
    this.doc = Automerge.change(this.doc, 'Announce pool', (doc) => {
      doc.pools[pool.poolId] = pool;
    });

    // Broadcast announcement to all peers
    const message: PoolAnnounceMessage = {
      type: 'pool_announce',
      from: this.config.instance.id,
      timestamp: Date.now(),
      messageId: uuid(),
      pool,
    };
    this.broadcastMessage(message);

    // Sync CRDT state
    this.syncAllPeers();

    this.emit('pool:announced', pool);
  }

  /**
   * Update pool metadata in federation
   */
  updatePool(poolId: string, updates: Partial<FederatedPoolMetadata>): void {
    this.doc = Automerge.change(this.doc, 'Update pool', (doc) => {
      if (doc.pools[poolId]) {
        Object.assign(doc.pools[poolId], updates, { updatedAt: Date.now() });
      }
    });

    this.syncAllPeers();

    const pool = this.doc.pools[poolId];
    if (pool) {
      this.emit('pool:updated', pool);
    }
  }

  /**
   * Get all federated pools
   */
  getFederatedPools(): FederatedPoolMetadata[] {
    return Object.values(this.doc.pools);
  }

  /**
   * Get a specific federated pool
   */
  getFederatedPool(poolId: string): FederatedPoolMetadata | undefined {
    return this.doc.pools[poolId];
  }

  /**
   * Get all known instances
   */
  getInstances(): InstanceId[] {
    return Object.values(this.doc.instances);
  }

  /**
   * Get connected peer count
   */
  getConnectedPeerCount(): number {
    let count = 0;
    for (const [, peer] of this.peers) {
      if (peer.connected) count++;
    }
    return count;
  }

  /**
   * Request to join a pool on a remote instance
   * Privacy: Uses anonymous Freebird token (no instance ID) and encrypts
   * profile data with pool owner's public key.
   */
  async requestJoin(
    poolId: string,
    publicKey: string,
    displayName: string,
    bio?: string,
    freebirdProof?: string
  ): Promise<JoinResponseMessage> {
    const pool = this.doc.pools[poolId];
    if (!pool) {
      throw new Error('Pool not found in federation');
    }

    if (!pool.ownerPublicKey) {
      throw new Error('Pool owner public key not available for encryption');
    }

    const ownerPeer = this.peers.get(pool.ownerInstance);
    if (!ownerPeer?.connected) {
      throw new Error('Pool owner instance not connected');
    }

    // Get fresh anonymous auth token
    const authToken = await this.authProvider.getAuthToken(true);

    // Encrypt sensitive profile data with pool owner's public key
    const payload: JoinRequestPayload = {
      displayName,
      bio,
      freebirdProof,
    };
    const encryptedBox = encryptForPublicKey(JSON.stringify(payload), pool.ownerPublicKey);
    const encryptedPayload = serializeEncryptedBox(encryptedBox);

    const request: AnonymousJoinRequestMessage = {
      type: 'join_request',
      authToken,
      timestamp: Date.now(),
      messageId: uuid(),
      poolId,
      publicKey,
      encryptedPayload,
    };

    return this.sendAndWaitForResponse(pool.ownerInstance, request);
  }

  /**
   * Relay match tokens to the pool's owner instance
   * Privacy: Uses anonymous Freebird token and random delay.
   */
  async relayTokens(
    poolId: string,
    matchTokens: string[],
    nullifier: string
  ): Promise<void> {
    const pool = this.doc.pools[poolId];
    if (!pool) {
      throw new Error('Pool not found in federation');
    }

    // If we own this pool, no need to relay
    if (pool.ownerInstance === this.config.instance.id) {
      return;
    }

    // Get fresh anonymous auth token
    const authToken = await this.authProvider.getAuthToken(true);

    // Random delay (5s to 60s) to frustrate timing analysis
    const minDelay = 5_000;
    const maxDelay = 60_000;
    const randomDelay = minDelay + Math.floor(Math.random() * (maxDelay - minDelay));
    await new Promise(resolve => setTimeout(resolve, randomDelay));

    const relay: AnonymousTokenRelayMessage = {
      type: 'token_relay',
      authToken,
      timestamp: Date.now(),
      messageId: uuid(),
      poolId,
      matchTokens,
      nullifier,
    };

    await this.sendToPeer(pool.ownerInstance, relay);
  }

  /**
   * Verify an incoming message's Freebird auth token
   */
  async verifyAuthToken(msg: AnonymousFederationMessage): Promise<boolean> {
    return this.authProvider.verifyAuthToken(msg.authToken);
  }

  /**
   * Broadcast match results to federation
   */
  broadcastResults(
    poolId: string,
    matchedTokens: string[],
    witnessProof?: ResultNotifyMessage['witnessProof']
  ): void {
    const message: ResultNotifyMessage = {
      type: 'result_notify',
      from: this.config.instance.id,
      timestamp: Date.now(),
      messageId: uuid(),
      poolId,
      matchedTokens,
      witnessProof,
    };

    this.broadcastMessage(message);
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private connectToPeer(endpoint: string): void {
    if (!this.running) return;

    try {
      const ws = new WebSocket(endpoint);

      ws.on('open', () => {
        // Send handshake with our instance info
        const handshake = JSON.stringify({
          type: 'handshake',
          instance: this.config.instance,
        });
        ws.send(handshake);
      });

      ws.on('message', (data) => {
        this.handleMessage(ws, data.toString(), endpoint);
      });

      ws.on('close', () => {
        // Find and mark peer as disconnected
        for (const [instanceId, peer] of this.peers) {
          if (peer.instance.endpoint === endpoint) {
            peer.connected = false;
            this.peerSockets.delete(instanceId);
            this.emit('peer:disconnected', instanceId);
            // Attempt reconnect after delay
            setTimeout(() => this.connectToPeer(endpoint), 5000 * (peer.retryCount + 1));
            peer.retryCount++;
            break;
          }
        }
      });

      ws.on('error', (err) => {
        console.error(`Federation peer connection error: ${err.message}`);
      });
    } catch (err) {
      console.error(`Failed to connect to peer ${endpoint}:`, err);
    }
  }

  private handleIncomingConnection(ws: WebSocket, _url: string): void {
    // Track which instance this connection belongs to (set after handshake)
    let connectedInstanceId: string | null = null;

    ws.on('message', (data) => {
      const instanceId = this.handleMessage(ws, data.toString());
      if (instanceId && !connectedInstanceId) {
        connectedInstanceId = instanceId;
      }
    });

    ws.on('close', () => {
      if (connectedInstanceId) {
        const peer = this.peers.get(connectedInstanceId);
        if (peer) {
          peer.connected = false;
          this.peerSockets.delete(connectedInstanceId);
          this.emit('peer:disconnected', connectedInstanceId);
        }
      }
    });
  }

  private handleMessage(ws: WebSocket, data: string, endpoint?: string): string | null {
    try {
      const message = JSON.parse(data);

      // Handle handshake
      if (message.type === 'handshake') {
        const instance = message.instance as InstanceId;
        this.peers.set(instance.id, {
          instance: endpoint ? { ...instance, endpoint } : instance,
          connected: true,
          lastPing: Date.now(),
          retryCount: 0,
        });
        this.peerSockets.set(instance.id, ws);
        this.syncStates.set(instance.id, Automerge.initSyncState());

        // Add instance to CRDT
        this.doc = Automerge.change(this.doc, 'Add instance', (doc) => {
          doc.instances[instance.id] = instance;
        });

        this.emit('peer:connected', instance.id);

        // Send initial sync
        this.syncWithPeer(instance.id);
        return instance.id;
      }

      // Check if this is an anonymous message (has authToken, no from)
      if (isAnonymousMessage(message)) {
        this.handleAnonymousMessage(message).catch(err => {
          console.error('Failed to handle anonymous message:', err);
        });
        return null;
      }

      // Handle identified federation messages
      const msg = message as FederationMessage;

      // Handle identified federation messages (sync, announce, etc.)
      // Note: join_request and token_relay are always anonymous (handled above)
      switch (msg.type) {
        case 'sync':
          this.handleSyncMessage(msg as SyncMessage, ws);
          break;
        case 'pool_announce':
          this.handlePoolAnnounce(msg as PoolAnnounceMessage);
          break;
        case 'result_notify':
          this.emit('results:received', msg as ResultNotifyMessage);
          break;
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong', from: this.config.instance.id }));
          break;
        case 'pong':
          const peer = this.peers.get(msg.from);
          if (peer) peer.lastPing = Date.now();
          break;
        case 'join_response':
          // Handle response to our join request
          const pending = this.pendingResponses.get(msg.messageId);
          if (pending) {
            pending.resolve(msg);
            this.pendingResponses.delete(msg.messageId);
          }
          break;
      }
    } catch (err) {
      console.error('Failed to handle federation message:', err);
    }
    return null;
  }

  /**
   * Handle an incoming federation message (all messages use anonymous tokens)
   */
  private async handleAnonymousMessage(msg: AnonymousFederationMessage): Promise<void> {
    // Verify the Freebird auth token
    const isValid = await this.verifyAuthToken(msg);
    if (!isValid) {
      console.warn('Invalid auth token, dropping message');
      return;
    }

    // Route to appropriate handler
    switch (msg.type) {
      case 'join_request':
        this.emit('join:request', msg as AnonymousJoinRequestMessage);
        break;
      case 'token_relay':
        this.emit('tokens:relayed', msg as AnonymousTokenRelayMessage);
        break;
      default:
        console.warn(`Unhandled anonymous message type: ${msg.type}`);
    }
  }

  private handleSyncMessage(msg: SyncMessage, ws: WebSocket): void {
    const syncState = this.syncStates.get(msg.from) || Automerge.initSyncState();
    const syncData = Buffer.from(msg.syncData, 'base64');

    // Apply incoming sync message
    const [newDoc, newSyncState, _patch] = Automerge.receiveSyncMessage(
      this.doc,
      syncState,
      syncData
    );

    this.doc = newDoc;
    this.syncStates.set(msg.from, newSyncState);

    // Generate response sync message if needed
    const [nextSyncState, outgoing] = Automerge.generateSyncMessage(
      this.doc,
      newSyncState
    );

    if (outgoing) {
      this.syncStates.set(msg.from, nextSyncState);
      const response: SyncMessage = {
        type: 'sync',
        from: this.config.instance.id,
        timestamp: Date.now(),
        messageId: uuid(),
        syncData: Buffer.from(outgoing).toString('base64'),
      };
      ws.send(JSON.stringify(response));
    }

    this.emit('state:changed', this.doc);
  }

  private handlePoolAnnounce(msg: PoolAnnounceMessage): void {
    // Update CRDT with new pool
    this.doc = Automerge.change(this.doc, 'Pool announced', (doc) => {
      doc.pools[msg.pool.poolId] = msg.pool;
    });

    this.emit('pool:announced', msg.pool);
  }

  /**
   * Privacy enhancement: Generate random delay for federation messages
   * This adds timing noise to frustrate traffic analysis
   */
  private getTimingNoise(): number {
    const minDelay = 100;    // 100ms minimum
    const maxDelay = 2000;   // 2s maximum
    return minDelay + Math.floor(Math.random() * (maxDelay - minDelay));
  }

  private async syncWithPeer(instanceId: string): Promise<void> {
    const ws = this.peerSockets.get(instanceId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return;
    }

    const syncState = this.syncStates.get(instanceId) || Automerge.initSyncState();
    const [newSyncState, message] = Automerge.generateSyncMessage(this.doc, syncState);

    if (message) {
      await new Promise(resolve => setTimeout(resolve, this.getTimingNoise()));

      this.syncStates.set(instanceId, newSyncState);
      const syncMsg: SyncMessage = {
        type: 'sync',
        from: this.config.instance.id,
        timestamp: Date.now(),
        messageId: uuid(),
        syncData: Buffer.from(message).toString('base64'),
      };
      ws.send(JSON.stringify(syncMsg));
    }
  }

  private syncAllPeers(): void {
    for (const [instanceId, peer] of this.peers) {
      if (peer.connected) {
        this.syncWithPeer(instanceId).catch(err => {
          console.error(`Failed to sync with peer ${instanceId}:`, err);
        });
      }
    }
    this.emit('state:changed', this.doc);
  }

  private async broadcastMessage(message: FederationMessage): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, this.getTimingNoise()));

    const data = JSON.stringify(message);
    for (const [instanceId, ws] of this.peerSockets) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(data);
        } catch (err) {
          console.error(`Failed to broadcast to ${instanceId}:`, err);
        }
      }
    }
  }

  private async sendToPeer(
    instanceId: string,
    message: FederationMessage | AnonymousFederationMessage
  ): Promise<void> {
    const ws = this.peerSockets.get(instanceId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Peer ${instanceId} not connected`);
    }

    await new Promise(resolve => setTimeout(resolve, this.getTimingNoise()));
    ws.send(JSON.stringify(message));
  }

  private async sendAndWaitForResponse<T>(
    instanceId: string,
    request: FederationMessage | AnonymousFederationMessage
  ): Promise<T> {
    const ws = this.peerSockets.get(instanceId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Peer ${instanceId} not connected`);
    }

    return new Promise((resolve, reject) => {
      const messageId = request.messageId;
      const timeout = setTimeout(() => {
        this.pendingResponses.delete(messageId);
        reject(new Error('Request timed out'));
      }, 30000);

      this.pendingResponses.set(messageId, {
        resolve: (value) => {
          clearTimeout(timeout);
          resolve(value as T);
        },
        reject: (err) => {
          clearTimeout(timeout);
          reject(err);
        },
      });

      ws.send(JSON.stringify(request));
    });
  }
}
