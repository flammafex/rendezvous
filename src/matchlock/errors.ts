export class MatchlockError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'MatchlockError';
  }
}

export class InvalidKeyError extends MatchlockError {
  constructor(message: string) {
    super(message, 'INVALID_KEY');
    this.name = 'InvalidKeyError';
  }
}

export class InvalidTokenError extends MatchlockError {
  constructor(message: string) {
    super(message, 'INVALID_TOKEN');
    this.name = 'InvalidTokenError';
  }
}

export class DecryptionError extends MatchlockError {
  constructor(message: string) {
    super(message, 'DECRYPTION_FAILED');
    this.name = 'DecryptionError';
  }
}
