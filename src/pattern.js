/**
 * Search pattern parsing, validation and compilation for v3 addresses.
 *
 * A pattern describes the characters an onion address must start with
 * (prefix: "^string") or end with (suffix: "string$"). "^string$" is accepted
 * as an exact match, which requires a full 56-character address.
 *
 * v3 addresses have two hard constraints in their tail (the version byte):
 *   - the last character is always "d" (VERSION = 0x03),
 *   - the character before it is always one of "a", "i", "q", "y"
 *     (it shares bits with the version byte).
 * Patterns that violate them can never match and are rejected up front.
 *
 * Compilation projects the pattern onto the 280-bit address space: the
 * requested characters become a bit mask over the 35 address bytes
 * (PUBKEY | CHECKSUM | VERSION), so matching only compares the bytes the
 * pattern touches. Prefixes of up to 51 characters live entirely inside the
 * Ed25519 public key, which lets the search skip the SHA3 checksum for them.
 */
import {
  ADDRESS_BYTES,
  ADDRESS_LENGTH,
  BASE32_ALPHABET,
  PUBLIC_KEY_BYTES,
} from './onion.js';

const ADDRESS_BITS = ADDRESS_BYTES * 8;
const BITS_PER_CHAR = 5;
const CHAR_SPACE = 2 ** BITS_PER_CHAR;

/** Every v3 address ends with this character (VERSION = 0x03). */
export const SUFFIX_LAST_CHAR = 'd';
/** Possible values for the character before the last one. */
export const SUFFIX_PENULTIMATE_CHARS = 'aiqy';

export class PatternError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PatternError';
  }
}

/**
 * Parse and compile a pattern. Throws PatternError when the pattern cannot
 * possibly match a v3 onion address.
 */
export function parsePattern(raw) {
  if (typeof raw !== 'string') {
    throw new PatternError('Search pattern must be a string');
  }
  const input = raw.trim();
  if (input.length === 0) {
    throw new PatternError('Search pattern must not be empty');
  }

  const hasStart = input.startsWith('^');
  const hasEnd = input.endsWith('$');
  if (!hasStart && !hasEnd) {
    throw new PatternError(
      `Invalid pattern "${raw}": start it with "^" to match the beginning of an address, ` +
        'or end it with "$" to match the end (for example "^dead" or "beef$")',
    );
  }

  const body = input
    .slice(hasStart ? 1 : 0, hasEnd ? input.length - 1 : input.length)
    .toLowerCase();

  if (body.length === 0) {
    throw new PatternError(`Invalid pattern "${raw}": the search string is empty`);
  }
  for (const char of body) {
    if (!BASE32_ALPHABET.includes(char)) {
      throw new PatternError(
        `Invalid character "${char}" in "${raw}": v3 onion addresses use lowercase base32, ` +
          'so the allowed characters are a-z and 2-7',
      );
    }
  }
  if (body.length > ADDRESS_LENGTH) {
    throw new PatternError(
      `Pattern "${body}" is ${body.length} characters long but v3 onion addresses ` +
        `are exactly ${ADDRESS_LENGTH} characters`,
    );
  }

  let mode;
  if (hasStart && hasEnd) {
    if (body.length !== ADDRESS_LENGTH) {
      throw new PatternError(
        `Pattern "${raw}" uses both "^" and "$": that is only valid for a full ` +
          `${ADDRESS_LENGTH}-character address (exact match), but "${body}" is ` +
          `${body.length} characters`,
      );
    }
    mode = 'exact';
  } else {
    mode = hasStart ? 'prefix' : 'suffix';
  }

  if (mode !== 'prefix') {
    validateSuffixConstraints(raw, body);
  }

  return compile({ raw: input, body, mode });
}

function validateSuffixConstraints(raw, body) {
  const last = body[body.length - 1];
  if (last !== SUFFIX_LAST_CHAR) {
    throw new PatternError(
      `Pattern "${raw}" can never match: every v3 onion address ends with ` +
        `"${SUFFIX_LAST_CHAR}" (the fixed version byte 0x03)`,
    );
  }
  if (body.length >= 2) {
    const penultimate = body[body.length - 2];
    if (!SUFFIX_PENULTIMATE_CHARS.includes(penultimate)) {
      throw new PatternError(
        `Pattern "${raw}" can never match: the second-to-last character of a v3 ` +
          `onion address is always one of "${SUFFIX_PENULTIMATE_CHARS.split('').join('", "')}" ` +
          '(bits shared with the version byte)',
      );
    }
  }
}

function compile({ raw, body, mode }) {
  const length = body.length;
  const startBit = mode === 'suffix' ? ADDRESS_BITS - length * BITS_PER_CHAR : 0;
  const comparisons = buildComparisons(body, startBit);
  const needsTail = comparisons.some(([byte]) => byte >= PUBLIC_KEY_BYTES);
  const space = patternSpace(mode, length);
  const bodyValues = Uint8Array.from(body, (char) => BASE32_ALPHABET.indexOf(char));

  return Object.freeze({
    raw,
    body,
    mode,
    length,
    /** How many addresses match the pattern (out of 2^280). */
    space,
    /** Probability that a uniformly random address matches. */
    probability: 1 / space,
    /** Expected number of candidates until the first match. */
    expectedAttempts: space,
    /**
     * True when matching requires the checksum+version tail; false when the
     * pattern lives entirely inside the public key (prefixes up to 51 chars).
     */
    needsTail,

    /**
     * Fast check against the digest bytes. Accepts the 35 address bytes
     * (PUBKEY | CHECKSUM | VERSION), or just the 32 public key bytes when
     * needsTail is false.
     */
    match(bytes) {
      for (let i = 0; i < comparisons.length; i += 1) {
        const [byte, mask, value] = comparisons[i];
        if ((bytes[byte] & mask) !== value) return false;
      }
      return true;
    },

    /**
     * How close a candidate is to the pattern, counted in matching characters
     * from the start (prefix mode) or from the end (suffix mode). This is the
     * live "closeness" metric shown while searching.
     *
     * The 5-bit groups are extracted straight from the address bytes and the
     * loop exits at the first mismatch (on random candidates that is after
     * ~1 character), so this costs nanoseconds per candidate — far cheaper
     * than encoding the whole address to a base32 string.
     */
    score(bytes) {
      if (mode === 'suffix') return suffixScore(bytes, bodyValues);
      if (mode === 'exact') {
        return Math.min(prefixScore(bytes, bodyValues), suffixScore(bytes, bodyValues));
      }
      return prefixScore(bytes, bodyValues);
    },

    toString() {
      if (mode === 'prefix') return `^${body}`;
      if (mode === 'suffix') return `${body}$`;
      return `^${body}$`;
    },
  });
}

/**
 * Number of addresses matching a pattern.
 *
 * Prefixes: every character carries 5 uniform bits of the public key (or
 * checksum), so the space is the plain 32^length.
 *
 * Suffixes: the last 8 bits are the fixed version byte, which removes one
 * byte of entropy from the search: the space is 2^(5·length − 8). A suffix of
 * just "d" always matches (space 1), and a suffix of two valid characters
 * (e.g. "yd") only needs the 2 checksum bits behind it (space 4).
 */
function patternSpace(mode, length) {
  if (mode === 'suffix') {
    return length === 1 ? 1 : 2 ** (BITS_PER_CHAR * length - 8);
  }
  return CHAR_SPACE ** length;
}

/**
 * Translate the pattern characters into one [byte, mask, value] comparison
 * per touched address byte. Each base32 character carries 5 bits, MSB first,
 * exactly like the encoder walks the bytes.
 */
function buildComparisons(body, startBit) {
  const masks = new Uint8Array(ADDRESS_BYTES);
  const values = new Uint8Array(ADDRESS_BYTES);
  let bit = startBit;

  for (const char of body) {
    const value = BASE32_ALPHABET.indexOf(char);
    for (let shift = BITS_PER_CHAR - 1; shift >= 0; shift -= 1) {
      const byte = bit >> 3;
      const offset = 7 - (bit & 7);
      masks[byte] |= 1 << offset;
      if ((value >> shift) & 1) values[byte] |= 1 << offset;
      bit += 1;
    }
  }

  const comparisons = [];
  for (let byte = 0; byte < ADDRESS_BYTES; byte += 1) {
    if (masks[byte] !== 0) comparisons.push([byte, masks[byte], values[byte]]);
  }
  return comparisons;
}

/**
 * Value of the 5-bit base32 group that starts at bit `bit` (MSB first),
 * extracted directly from the address bytes. Reads two bytes, so callers
 * should pass a buffer with one spare byte past the address to keep the
 * lookup in bounds.
 */
function valueAt(bytes, bit) {
  const byte = bit >> 3;
  return (((bytes[byte] << 8) | bytes[byte + 1]) >> (11 - (bit & 7))) & 31;
}

function prefixScore(bytes, values) {
  let i = 0;
  while (i < values.length && valueAt(bytes, i * BITS_PER_CHAR) === values[i]) i += 1;
  return i;
}

function suffixScore(bytes, values) {
  const count = values.length;
  let i = 0;
  while (
    i < count &&
    valueAt(bytes, ADDRESS_BITS - BITS_PER_CHAR * (i + 1)) === values[count - 1 - i]
  ) {
    i += 1;
  }
  return i;
}
