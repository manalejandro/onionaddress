import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { addressFromPublicKey, base32Encode, generateKeyPair, publicKeyBytes } from '../src/onion.js';

function opensslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Independent cross-check: OpenSSL extracts the raw Ed25519 public key from
 * the SPKI DER encoding, and computes the SHA3-256 checksum with a plain
 * `openssl dgst` pipeline. The assembled address must equal the one computed
 * by src/onion.js.
 */
test(
  'address derivation agrees with OpenSSL',
  { skip: opensslAvailable() ? false : 'openssl is not available' },
  () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'onionaddress-openssl-'));
    try {
      const { privateKey, publicKey } = generateKeyPair();
      const keyPath = path.join(dir, 'key.pem');
      writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));

      // 1. Raw public key as seen by OpenSSL (SPKI DER, trailing 32 bytes).
      const spki = execFileSync('openssl', ['pkey', '-in', keyPath, '-pubout', '-outform', 'DER']);
      const publicKeyFromOpenssl = spki.subarray(spki.length - 32);
      assert.deepEqual(publicKeyBytes(publicKey), publicKeyFromOpenssl);

      // 2. Checksum via `openssl dgst -sha3-256` over the exact spec input.
      const checksumInputPath = path.join(dir, 'checksum-input.bin');
      const digestPath = path.join(dir, 'digest.bin');
      writeFileSync(
        checksumInputPath,
        Buffer.concat([Buffer.from('.onion checksum'), publicKeyFromOpenssl, Buffer.from([0x03])]),
      );
      execFileSync('openssl', ['dgst', '-sha3-256', '-binary', '-out', digestPath, checksumInputPath]);
      const digest = readFileSync(digestPath);

      const expected = base32Encode(
        Buffer.concat([publicKeyFromOpenssl, digest.subarray(0, 2), Buffer.from([0x03])]),
      );
      assert.equal(addressFromPublicKey(publicKey), expected);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
