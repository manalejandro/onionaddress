import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  ADDRESS_LENGTH,
  CHECKSUM_PREFIX,
  addressBytesForPublicKey,
  addressFromPrivateKey,
  addressFromPublicKey,
  base32Encode,
  checksumForPublicKey,
  generateKeyPair,
  privateKeyFromSeed,
  publicKeyBytes,
  publicKeyFileBytes,
  secretKeyFileBytes,
  seedFromPrivateKey,
  sha3_256,
} from '../src/onion.js';

test('base32Encode matches RFC 4648 base32, lowercase and without padding', () => {
  assert.equal(base32Encode(Buffer.alloc(35)), 'a'.repeat(56));
  assert.equal(base32Encode(Buffer.alloc(35, 0xff)), '7'.repeat(56));
  assert.equal(base32Encode(Buffer.from([0x00])), 'aa');
  assert.equal(base32Encode(Buffer.from([0x01])), 'ae');
});

test('generated keys derive a 56-character base32 address ending in "d"', () => {
  const { privateKey, publicKey } = generateKeyPair();
  const address = addressFromPublicKey(publicKey);
  assert.equal(address.length, ADDRESS_LENGTH);
  assert.match(address, /^[a-z2-7]{56}$/);
  assert.ok(address.endsWith('d'), 'every v3 address ends with the version character');
  assert.equal(addressFromPrivateKey(privateKey), address);
});

/**
 * Cross-implementation vector: seed 0x42 * 32 pushed through Python
 * (cryptography + hashlib.sha3_256 + base64.b32encode) produces the values
 * below. They must match Node's derivation byte for byte.
 */
test('matches the independent v3 test vector (seed 0x42 x32)', () => {
  const seed = Buffer.from('42'.repeat(32), 'hex');
  const privateKey = privateKeyFromSeed(seed);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyRaw = publicKeyBytes(publicKey);

  assert.equal(
    publicKeyRaw.toString('hex'),
    '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12',
  );
  assert.equal(checksumForPublicKey(publicKeyRaw).toString('hex'), 'efc8');
  assert.equal(
    addressFromPrivateKey(privateKey),
    'efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad',
  );
});

test('public key and seed extraction agree with the JWK export', () => {
  const { privateKey, publicKey } = generateKeyPair();
  const jwkPublic = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const jwkPrivate = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  assert.deepEqual(publicKeyBytes(publicKey), jwkPublic);
  assert.deepEqual(seedFromPrivateKey(privateKey), jwkPrivate);
});

test('address bytes are PUBKEY | CHECKSUM | VERSION', () => {
  const seed = Buffer.from('42'.repeat(32), 'hex');
  const publicKey = crypto.createPublicKey(privateKeyFromSeed(seed));
  const publicKeyRaw = publicKeyBytes(publicKey);
  const bytes = addressBytesForPublicKey(publicKeyRaw);

  assert.equal(bytes.length, 35);
  assert.deepEqual(bytes.subarray(0, 32), publicKeyRaw);
  assert.equal(bytes.subarray(32, 34).toString('hex'), 'efc8');
  assert.equal(bytes[34], 0x03);
});

/**
 * The mining hot loop assembles the SHA3 input into a reusable 48-byte
 * buffer instead of calling the canonical helper. This guards the exact byte
 * layout (".onion checksum" | PUBKEY | 0x03) and that sha3_256 returns raw
 * bytes rather than a hex string.
 */
test('worker-style checksum assembly matches the canonical checksum', () => {
  const hashInput = Buffer.allocUnsafe(CHECKSUM_PREFIX.length + 32 + 1);
  CHECKSUM_PREFIX.copy(hashInput);
  hashInput[hashInput.length - 1] = 0x03;

  for (let i = 0; i < 50; i += 1) {
    const publicKey = publicKeyBytes(generateKeyPair().publicKey);
    publicKey.copy(hashInput, CHECKSUM_PREFIX.length);
    const digest = sha3_256(hashInput);
    assert.ok(Buffer.isBuffer(digest), 'sha3_256 must return a Buffer');
    assert.equal(digest.length, 32);
    assert.deepEqual(digest.subarray(0, 2), checksumForPublicKey(publicKey));
  }
});

test('Tor key files use the ed25519v1 format', () => {
  const seed = Buffer.from('42'.repeat(32), 'hex');
  const publicKey = publicKeyBytes(crypto.createPublicKey(privateKeyFromSeed(seed)));
  const secretFile = secretKeyFileBytes(seed, publicKey);
  const publicKeyFile = publicKeyFileBytes(publicKey);
  const secretHeader = Buffer.concat([Buffer.from('== ed25519v1-secret: type0 =='), Buffer.alloc(3)]);
  const publicHeader = Buffer.concat([Buffer.from('== ed25519v1-public: type0 =='), Buffer.alloc(3)]);

  assert.equal(secretFile.length, 96);
  assert.equal(publicKeyFile.length, 64);
  assert.deepEqual(secretFile.subarray(0, 32), secretHeader);
  assert.deepEqual(publicKeyFile.subarray(0, 32), publicHeader);
  assert.deepEqual(secretFile.subarray(32, 64), seed);
  assert.deepEqual(secretFile.subarray(64), publicKey);
  assert.deepEqual(publicKeyFile.subarray(32), publicKey);
});
