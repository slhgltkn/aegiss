export interface TokenContext {
      ip?: string;
      userAgent?: string;
}

export declare class VerificationError extends Error {
      constructor(message: string);
}

export declare const BLOCK_DURATION_MS: number;

export declare function sign(payload: string | Record<string, any>, secretHex: string, expiresInSec: number, context: TokenContext): string;

export declare function verify<T = any>(token: string, publicKeyHex: string, context?: TokenContext): T;

export declare function decode<T = any>(token: string): T;

export declare function encrypt(payload: string, secretHex: string): string;

export declare function decrypt(encryptedData: string, secretHex: string): string;

export declare function createVerifyMiddleware(publicKeyHex: string, options?: any): any;
export declare function getClientInfo(req: any): TokenContext;
export declare function clearBlockList(): void;
export declare function isBlocked(ip: string): boolean;
