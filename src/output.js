/**
 * Persist a found address as a ready-to-use Tor v3 hidden service directory:
 *
 *   output/<address>.onion/
 *     hostname              the .onion hostname
 *     hs_ed25519_secret_key Ed25519 secret key (96 bytes, 0600)
 *     hs_ed25519_public_key Ed25519 public key (64 bytes)
 *     metadata.json         search + key provenance
 *
 * The two key files use Tor's native "ed25519v1" format, so the directory can
 * be used directly as a hidden service directory.
 * Every match is also appended to output/found.log.
 */
import { appendFile, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  ONION_SUFFIX,
  checksumForPublicKey,
  publicKeyFileBytes,
  secretKeyFileBytes,
} from './onion.js';

const NOTE_TEXT =
  'hs_ed25519_secret_key holds the private key: keep it private and back it up. ' +
  'A distinctive vanity address is recognizable and therefore linkable — use it ' +
  'only where that is acceptable.';

export async function ensureOutputDir(outputDir) {
  await mkdir(outputDir, { recursive: true });
}

export async function saveResult({
  outputDir,
  address,
  seed,
  publicKey,
  pattern,
  attempts,
  attemptsByFinder,
  startedAt,
  foundAt = new Date(),
  version,
}) {
  const hostname = `${address}${ONION_SUFFIX}`;
  const dir = path.join(outputDir, hostname);
  await mkdir(dir, { recursive: true });

  await writeFile(path.join(dir, 'hostname'), `${hostname}\n`);

  const secretKeyPath = path.join(dir, 'hs_ed25519_secret_key');
  await writeFile(secretKeyPath, secretKeyFileBytes(seed, publicKey), { mode: 0o600 });
  await chmod(secretKeyPath, 0o600);

  await writeFile(path.join(dir, 'hs_ed25519_public_key'), publicKeyFileBytes(publicKey));

  const startedDate = startedAt instanceof Date ? startedAt : new Date(startedAt);
  const metadata = {
    generator: 'onionaddress',
    version,
    address: hostname,
    pattern: {
      raw: pattern.raw,
      mode: pattern.mode,
      value: pattern.body,
    },
    search: {
      attempts,
      attemptsByFinder,
      startedAt: startedDate.toISOString(),
      foundAt: foundAt.toISOString(),
      durationSeconds: Number(((foundAt.getTime() - startedDate.getTime()) / 1000).toFixed(3)),
    },
    key: {
      type: 'Ed25519',
      onionVersion: 3,
      checksum: checksumForPublicKey(publicKey).toString('hex'),
      publicKeyHex: publicKey.toString('hex'),
      secretKeyFile: 'hs_ed25519_secret_key',
      secretKeyFormat: 'ed25519v1-secret (seed || public key, 96 bytes)',
      publicKeyFile: 'hs_ed25519_public_key',
      publicKeyFormat: 'ed25519v1-public (64 bytes)',
    },
    note: NOTE_TEXT,
  };
  await writeFile(path.join(dir, 'metadata.json'), `${JSON.stringify(metadata, null, 2)}\n`);

  await appendFile(
    path.join(outputDir, 'found.log'),
    `${foundAt.toISOString()} ${hostname} pattern=${pattern.raw} attempts=${attempts}\n`,
  );

  return { dir, hostname };
}

/**
 * Patch metadata.json once the run has finished, when exact totals (attempts
 * across all workers) are known.
 */
export async function reviseMetadata(dir, patch) {
  const metadataPath = path.join(dir, 'metadata.json');
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  metadata.search = { ...metadata.search, ...patch };
  await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
}
