export function generateKeys(): { publicKey: string; privateKey: string };
export function encrypt(plaintext: Buffer | Uint8Array, key: Buffer | string): string;
export function decrypt(packed: string, key: Buffer | string): Buffer;
export function sign(
  payload: Record<string, unknown>,
  privateKey: string,
  options: { clientInfo: { ip: string; userAgent: string }; expiresInSeconds?: number }
): string;
export function verify(
  token: string,
  publicKey: string,
  currentClientInfo: { ip: string; userAgent: string },
  options?: { minIat?: number; revokedJtis?: Set<string> | ((jti: string) => boolean) }
): Record<string, unknown>;
export function hashFingerprint(input: string): string;
export function toBase64Url(buf: Buffer | Uint8Array): string;
export function fromBase64Url(str: string): Buffer;
export function createVerifyMiddleware(
  publicKey: string,
  options?: { minIat?: number; revokedJtis?: Set<string> | ((jti: string) => boolean); maxFailedAttempts?: number }
): (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => void;
export function getClientInfo(req: { headers: Record<string, string | undefined>; socket?: { remoteAddress?: string } }): { ip: string; userAgent: string };
export function clearBlockList(): void;
export function isBlocked(ip: string): boolean;
export class VerificationError extends Error {}
export const CHACHA_KEY_LENGTH: number;
export const CHACHA_IV_LENGTH: number;
export const AUTH_TAG_LENGTH: number;
export const BLOCK_DURATION_MS: number;
