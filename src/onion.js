/**
 * Tor v3 onion service primitives.
 *
 * A v3 onion address is derived as:
 *
 *   onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
 *
 * where:
 *   PUBKEY   = 32-byte Ed25519 public key
 *   CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
 *   VERSION  = 0x03
 *
 * 35 bytes encode to exactly 56 base32 characters (lowercase, no padding).
 * Because the version byte is fixed, every v3 address ends with "d".
 */
import crypto from 'node:crypto';

export const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
export const ADDRESS_LENGTH = 56; // without the ".onion" suffix
export const ONION_SUFFIX = '.onion';
export const HOSTNAME_LENGTH = ADDRESS_LENGTH + ONION_SUFFIX.length; // 62
export const PUBLIC_KEY_BYTES = 32;
export const CHECKSUM_BYTES = 2;
export const ADDRESS_BYTES = PUBLIC_KEY_BYTES + CHECKSUM_BYTES + 1; // 35
export const VERSION_BYTE = 0x03;

export const CHECKSUM_PREFIX = Buffer.from('.onion checksum');
const VERSION_BUFFER = Buffer.from([VERSION_BYTE]);

// Fixed DER prefixes: ed25519 SPKI is 44 bytes, PKCS#8 is 48 bytes; the raw
// key material always sits in the trailing 32 bytes.
const SPKI_LENGTH = 44;
const PKCS8_LENGTH = 48;

/**
 * Generate a fresh Ed25519 key pair, as required by v3 hidden services.
 */
export function generateKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

/**
 * Raw 32-byte Ed25519 public key (the bytes that start an onion address).
 */
export function publicKeyBytes(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return der.subarray(SPKI_LENGTH - PUBLIC_KEY_BYTES);
}

/**
 * Raw 32-byte Ed25519 seed (the private scalar seed) behind a private key.
 */
export function seedFromPrivateKey(privateKey) {
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  return der.subarray(PKCS8_LENGTH - PUBLIC_KEY_BYTES);
}

/**
 * Build a private KeyObject from a raw 32-byte Ed25519 seed.
 */
export function privateKeyFromSeed(seed) {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS#8 prefix
    seed,
  ]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

/**
 * One-shot SHA3-256 returning raw bytes.
 *
 * Node's crypto.hash() is about twice as fast as the streaming API on the
 * small inputs used while mining, but its default output is a hex *string*;
 * ask for 'buffer' explicitly and probe once at load time, falling back to
 * createHash() where that is not supported.
 */
export const sha3_256 = (() => {
  if (typeof crypto.hash === 'function') {
    try {
      if (Buffer.isBuffer(crypto.hash('sha3-256', CHECKSUM_PREFIX, 'buffer'))) {
        return (input) => crypto.hash('sha3-256', input, 'buffer');
      }
    } catch {
      // Fall through to the streaming implementation below.
    }
  }
  return (input) => crypto.createHash('sha3-256').update(input).digest();
})();

/**
 * v3 checksum: the first two bytes of SHA3-256(".onion checksum" | PUBKEY | VERSION).
 */
export function checksumForPublicKey(publicKey) {
  const digest = sha3_256(Buffer.concat([CHECKSUM_PREFIX, publicKey, VERSION_BUFFER]));
  return digest.subarray(0, CHECKSUM_BYTES);
}

/**
 * The 35 address bytes for a public key: PUBKEY | CHECKSUM | VERSION.
 * Pass a reusable `out` buffer to avoid allocations in hot loops.
 */
export function addressBytesForPublicKey(publicKey, out = Buffer.allocUnsafe(ADDRESS_BYTES)) {
  publicKey.copy(out, 0);
  checksumForPublicKey(publicKey).copy(out, PUBLIC_KEY_BYTES);
  out[ADDRESS_BYTES - 1] = VERSION_BYTE;
  return out;
}

/**
 * RFC 4648 base32 encoding, lowercase and without padding.
 */
export function base32Encode(buffer) {
  let out = '';
  const totalBits = buffer.length * 8;
  for (let bit = 0; bit < totalBits; bit += 5) {
    let value = 0;
    for (let offset = 0; offset < 5; offset += 1) {
      const index = bit + offset;
      const current = index < totalBits ? (buffer[index >> 3] >> (7 - (index & 7))) & 1 : 0;
      value = (value << 1) | current;
    }
    out += BASE32_ALPHABET[value];
  }
  return out;
}

/**
 * The 56-character address (without ".onion") for a raw Ed25519 public key.
 */
export function addressFromPublicKeyBytes(publicKey) {
  return base32Encode(addressBytesForPublicKey(publicKey));
}

/**
 * The 56-character address (without ".onion") for a public KeyObject.
 */
export function addressFromPublicKey(publicKey) {
  return addressFromPublicKeyBytes(publicKeyBytes(publicKey));
}

/**
 * The 56-character address for a PEM/DER private key or a KeyObject.
 */
export function addressFromPrivateKey(privateKeyLike) {
  return addressFromPublicKey(crypto.createPublicKey(privateKeyLike));
}

/**
 * "abcdef….onion" for a 56-character address.
 */
export function hostnameFromAddress(address) {
  return `${address}${ONION_SUFFIX}`;
}

const SECRET_KEY_FILE_HEADER = Buffer.concat([
  Buffer.from('== ed25519v1-secret: type0 =='),
  Buffer.alloc(32 - '== ed25519v1-secret: type0 =='.length),
]);
const PUBLIC_KEY_FILE_HEADER = Buffer.concat([
  Buffer.from('== ed25519v1-public: type0 =='),
  Buffer.alloc(32 - '== ed25519v1-public: type0 =='.length),
]);

/**
 * Contents of Tor's hs_ed25519_secret_key file: 32-byte header followed by
 * the 64-byte expanded secret key (seed || public key). 96 bytes in total.
 */
export function secretKeyFileBytes(seed, publicKey) {
  return Buffer.concat([SECRET_KEY_FILE_HEADER, seed, publicKey]);
}

/**
 * Contents of Tor's hs_ed25519_public_key file: 32-byte header followed by
 * the 32-byte public key. 64 bytes in total.
 */
export function publicKeyFileBytes(publicKey) {
  return Buffer.concat([PUBLIC_KEY_FILE_HEADER, publicKey]);
}
