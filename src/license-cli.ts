/**
 * CLI commands for managing the agent-browser Pro license key.
 *
 * Usage:
 *   agent-browser license status
 *   agent-browser license set <key>
 *   agent-browser license remove
 */

import {
  validateLicense,
  getLimits,
  formatLicenseStatus,
  saveLicenseKey,
  removeLicenseKey,
  getLicenseKey,
  TIER_LIMITS,
} from './license.js';

function printUsage(): void {
  console.log(`
agent-browser license <command>

Commands:
  status               Show current license tier and limits
  activate <key>       Verify key server-side and save (recommended)
  set <key>            Save a Pro license key (offline only)
  remove               Remove license key (revert to free tier)

Environment variable:
  AGENT_BROWSER_LICENSE_KEY   Set license key without saving to disk

Get a license key at: https://authichain.com/agent-browser
`.trim());
}

function printStatus(): void {
  const info = validateLicense();
  const limits = getLimits(info);

  console.log('');
  console.log(formatLicenseStatus(info));
  console.log('');
  console.log('Limits:');
  console.log(
    `  Concurrent sessions : ${limits.maxConcurrentSessions === 0 ? 'Unlimited' : limits.maxConcurrentSessions}`
  );
  console.log(`  Session recording   : ${limits.sessionRecordingExport ? 'Yes' : 'No'}`);
  console.log(`  Cloud relay         : ${limits.cloudRelay ? 'Yes' : 'No'}`);

  if (info.expiresAt) {
    const daysLeft = Math.ceil((info.expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    console.log('');
    if (daysLeft <= 14) {
      console.log(`⚠  Expires in ${daysLeft} day(s). Renew at https://authichain.com/license`);
    } else {
      console.log(`   Expires: ${info.expiresAt.toLocaleDateString()}`);
    }
  }

  if (info.tier === 'free') {
    console.log('');
    console.log('Upgrade to Pro for unlimited concurrent sessions and more:');
    console.log('  https://authichain.com/license');
  }
  console.log('');
}

function setKey(key: string): void {
  if (!key || key.split('.').length !== 2) {
    console.error('Invalid license key format. Keys look like: <payload>.<signature>');
    process.exit(1);
  }

  saveLicenseKey(key);

  // Validate immediately so the user knows if the key is valid
  const info = validateLicense();
  if (!info.valid) {
    console.error(`License key saved but is invalid: ${info.reason}`);
    console.error('Check your key at https://authichain.com/license');
    process.exit(1);
  }

  console.log('');
  console.log(formatLicenseStatus(info));
  console.log('License key saved to ~/.agent-browser/license.key');
  console.log('');
}

function removeKey(): void {
  const existing = getLicenseKey();
  if (!existing) {
    console.log('No license key found (already on free tier).');
    return;
  }
  removeLicenseKey();
  console.log('License key removed. Reverted to free tier.');
}

/**
 * Verify a key server-side (revocation check) then save it.
 * Falls back to offline validation only if the server is unreachable.
 */
async function activateKey(key: string): Promise<void> {
  if (!key || key.split('.').length !== 2) {
    console.error('Invalid license key format. Keys look like: <payload>.<signature>');
    process.exit(1);
  }

  const verifyUrl = 'https://license.authichain.workers.dev/api/license/verify';
  let serverValid = false;
  let serverMsg = '';

  try {
    process.stdout.write('Verifying license with AuthiChain... ');
    const res = await fetch(`${verifyUrl}?key=${encodeURIComponent(key)}`, {
      signal: AbortSignal.timeout(8000),
    });
    const data: any = await res.json();
    if (res.ok && data.valid) {
      serverValid = true;
      const tierLabel = (data.tier as string).charAt(0).toUpperCase() + (data.tier as string).slice(1);
      serverMsg = `${tierLabel} license confirmed for ${data.email}`;
    } else {
      console.log('');
      console.error(`License rejected by server: ${data.error ?? 'invalid or revoked'}`);
      process.exit(1);
    }
  } catch {
    // Server unreachable — fall back to offline verification
    console.log('(offline)');
  }

  saveLicenseKey(key);
  const info = validateLicense();

  if (!info.valid) {
    console.error(`\nLicense key invalid: ${info.reason}`);
    process.exit(1);
  }

  console.log(serverMsg ? `\n✓  ${serverMsg}` : `\n${formatLicenseStatus(info)}`);
  console.log('License key saved to ~/.agent-browser/license.key\n');
}

export function runLicenseCli(args: string[]): void {
  const [command, ...rest] = args;

  switch (command) {
    case 'status':
    case undefined:
      printStatus();
      break;

    case 'activate': {
      const key = rest[0];
      if (!key) {
        console.error('Usage: agent-browser license activate <key>');
        process.exit(1);
      }
      activateKey(key).catch((err) => {
        console.error('Activation failed:', err.message);
        process.exit(1);
      });
      break;
    }

    case 'set': {
      const key = rest[0];
      if (!key) {
        console.error('Usage: agent-browser license set <key>');
        process.exit(1);
      }
      setKey(key);
      break;
    }

    case 'remove':
    case 'unset':
    case 'clear':
      removeKey();
      break;

    default:
      console.error(`Unknown license command: ${command}`);
      printUsage();
      process.exit(1);
  }
}
