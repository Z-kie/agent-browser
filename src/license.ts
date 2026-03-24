/**
 * License key verification for agent-browser.
 *
 * Verifies keys issued by the AuthiChain license-issuer Cloudflare Worker.
 * Format: <base64url(payload)>.<base64url(signature)>
 *
 * The matching signing counterpart lives in:
 *   workers/license-issuer/src/services/license.ts (AuthiChain repo)
 *
 * The public key is loaded from (in priority order):
 *   1. LICENSE_PUBLIC_KEY_PEM environment variable
 *   2. ~/.agent-browser/license-public.pem
 *   3. Bundled fallback (set at build time via AGENT_BROWSER_PUBLIC_KEY)
 */

import { webcrypto } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface LicensePayload {
  sub: string;        // email
  tier: LicenseTier;
  seats: number;      // 0 = unlimited
  exp: number;        // unix seconds
  iat: number;
  jti: string;
}

export type LicenseTier =
  | 'starter'
  | 'growth'
  | 'creator'
  | 'pro'
  | 'enterprise'
  | 'agency'
  | 'one_time';

export interface LicenseVerificationResult {
  valid: boolean;
  payload?: LicensePayload;
  reason?: string;
}

// ── Key loading ──────────────────────────────────────────────────────────────

function loadPublicKeyPem(): string | null {
  // 1. Env var
  if (process.env.LICENSE_PUBLIC_KEY_PEM) {
    return process.env.LICENSE_PUBLIC_KEY_PEM;
  }

  // 2. ~/.agent-browser/license-public.pem
  const homeKeyPath = path.join(os.homedir(), '.agent-browser', 'license-public.pem');
  if (existsSync(homeKeyPath)) {
    try {
      return readFileSync(homeKeyPath, 'utf8');
    } catch {
      // fall through
    }
  }

  // 3. Build-time bundled key
  if (process.env.AGENT_BROWSER_PUBLIC_KEY) {
    return process.env.AGENT_BROWSER_PUBLIC_KEY;
  }

  return null;
}

async function importPublicKey(pem: string): Promise<webcrypto.CryptoKey> {
  const der = Buffer.from(
    pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''),
    'base64'
  );
  return (webcrypto.subtle as SubtleCrypto).importKey(
    'spki',
    der.buffer as ArrayBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fromBase64url(b64: string): Buffer {
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const rem = padded.length % 4;
  const padded2 = rem ? padded + '='.repeat(4 - rem) : padded;
  return Buffer.from(padded2, 'base64');
}

// ── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify a license key string.
 * Returns `{ valid: true, payload }` on success, `{ valid: false, reason }` on failure.
 */
export async function verifyLicense(
  key: string
): Promise<LicenseVerificationResult> {
  if (!key || typeof key !== 'string') {
    return { valid: false, reason: 'No key provided' };
  }

  const parts = key.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'Malformed key: expected <payload>.<signature>' };
  }

  const [payloadB64, sigB64] = parts;

  // 1. Decode payload
  let payload: LicensePayload;
  try {
    payload = JSON.parse(fromBase64url(payloadB64).toString('utf8'));
  } catch {
    return { valid: false, reason: 'Malformed payload' };
  }

  // 2. Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    return { valid: false, reason: 'License expired', payload };
  }

  // 3. Verify signature
  const pemKey = loadPublicKeyPem();
  if (!pemKey) {
    // No public key available — treat as unverified but structurally valid
    // Callers can check result.reason to handle this case
    return { valid: false, reason: 'No public key configured — cannot verify signature' };
  }

  try {
    const publicKey = await importPublicKey(pemKey);
    const data = new TextEncoder().encode(payloadB64);
    const sig = fromBase64url(sigB64);

    const ok = await (webcrypto.subtle as SubtleCrypto).verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sig.buffer as ArrayBuffer,
      data.buffer as ArrayBuffer
    );

    if (!ok) {
      return { valid: false, reason: 'Invalid signature' };
    }
  } catch (err) {
    return { valid: false, reason: `Signature verification error: ${String(err)}` };
  }

  return { valid: true, payload };
}

/**
 * Check if a verified payload grants access to a given tier or above.
 *
 * Tier order (ascending): starter < growth = creator < pro < enterprise = agency
 */
const TIER_RANK: Record<LicenseTier, number> = {
  starter: 1,
  growth: 2,
  creator: 2,
  pro: 3,
  enterprise: 4,
  agency: 4,
  one_time: 1,
};

export function hasAccess(payload: LicensePayload, required: LicenseTier): boolean {
  return (TIER_RANK[payload.tier] ?? 0) >= (TIER_RANK[required] ?? 0);
}

/**
 * Convenience: verify key and check tier access in one call.
 */
export async function checkLicense(
  key: string,
  requiredTier: LicenseTier = 'starter'
): Promise<LicenseVerificationResult & { access: boolean }> {
  const result = await verifyLicense(key);
  const access = result.valid && result.payload
    ? hasAccess(result.payload, requiredTier)
    : false;
  return { ...result, access };
}
