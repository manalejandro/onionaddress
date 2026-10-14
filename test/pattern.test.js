import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { base32Encode } from '../src/onion.js';
import { PatternError, parsePattern } from '../src/pattern.js';

test('parses prefix patterns', () => {
  const pattern = parsePattern('^ab');
  assert.equal(pattern.mode, 'prefix');
  assert.equal(pattern.body, 'ab');
  assert.equal(pattern.length, 2);
  assert.equal(pattern.space, 32 ** 2);
  assert.equal(pattern.expectedAttempts, 32 ** 2);
  assert.equal(pattern.needsTail, false);
  assert.equal(pattern.toString(), '^ab');
});

test('parses suffix patterns and accounts for the fixed version bits', () => {
  const pattern = parsePattern('yd$');
  assert.equal(pattern.mode, 'suffix');
  assert.equal(pattern.body, 'yd');
  assert.equal(pattern.needsTail, true);
  // The last 8 bits of every address are the fixed version byte.
  assert.equal(pattern.space, 2 ** (5 * 2 - 8));
  assert.equal(pattern.toString(), 'yd$');
});

test('a "d$" suffix always matches', () => {
  const pattern = parsePattern('d$');
  assert.equal(pattern.space, 1);
  assert.equal(pattern.probability, 1);
});

test('suffix space grows by 32 per extra character', () => {
  assert.equal(parsePattern('ayd$').space, 2 ** 7);
  assert.equal(parsePattern('aayd$').space, 2 ** 12);
  assert.equal(parsePattern('aaayd$').space, 2 ** 17);
  assert.equal(parsePattern('aaayd$').needsTail, true);
});

test('exact patterns require all 56 characters', () => {
  const body = `${'a'.repeat(54)}yd`;
  const pattern = parsePattern(`^${body}$`);
  assert.equal(pattern.mode, 'exact');
  assert.equal(pattern.length, 56);
  assert.equal(pattern.needsTail, true);
  assert.throws(() => parsePattern('^abcdefghijklmnop$'), PatternError);
});

test('rejects suffixes that no v3 address can have', () => {
  assert.throws(() => parsePattern('abcx$'), /ends with "d"/);
  assert.throws(() => parsePattern('azd$'), /second-to-last/);
  assert.throws(() => parsePattern('^abcx$'), PatternError);
  assert.equal(parsePattern('ayd$').body, 'ayd');
});

test('is case-insensitive and trims whitespace', () => {
  assert.equal(parsePattern('  ^AB7  ').body, 'ab7');
  assert.equal(parsePattern('  AYD$ ').body, 'ayd');
  assert.equal(parsePattern(`^${'A'.repeat(54)}YD$`).mode, 'exact');
});

test('rejects patterns without ^ or $', () => {
  assert.throws(() => parsePattern('abc'), PatternError);
});

test('rejects invalid characters', () => {
  for (const bad of ['0', '1', '8', '9', '!', '-', '_', 'ñ']) {
    assert.throws(() => parsePattern(`^a${bad}`), PatternError, `"${bad}" must be rejected`);
  }
  // "l" is part of the base32 alphabet (a-z, 2-7).
  assert.equal(parsePattern('^l').body, 'l');
});

test('rejects patterns longer than an address', () => {
  assert.throws(() => parsePattern(`^${'a'.repeat(57)}`), PatternError);
});

test('rejects empty search strings', () => {
  assert.throws(() => parsePattern('^'), PatternError);
  assert.throws(() => parsePattern('$'), PatternError);
  assert.throws(() => parsePattern('^$'), PatternError);
});

test('compiled masks agree with base32 encoding', () => {
  const patterns = ['^a', '^7', '^ab', '^zz', 'abid$', 'yd$', 'ayd$', '^a7b', 'd$'];
  for (const raw of patterns) {
    const pattern = parsePattern(raw);
    for (let i = 0; i < 500; i += 1) {
      const bytes = crypto.randomBytes(35);
      const address = base32Encode(bytes);
      const expected =
        pattern.mode === 'prefix'
          ? address.startsWith(pattern.body)
          : pattern.mode === 'suffix'
            ? address.endsWith(pattern.body)
            : address === pattern.body;
      assert.equal(pattern.match(bytes), expected, `${raw} vs ${address}`);
    }
  }
});

test('score agrees with the reference string implementation', () => {
  const patterns = ['^a', '^ab', '^z7', `^${'a'.repeat(51)}`, 'yd$', 'abid$', 'ayd$', 'd$'];
  for (const raw of patterns) {
    const pattern = parsePattern(raw);
    for (let i = 0; i < 300; i += 1) {
      // 35 address bytes plus the spare byte the hot loop uses for lookups
      const bytes = crypto.randomBytes(36);
      const address = base32Encode(bytes.subarray(0, 35));
      const expected =
        pattern.mode === 'prefix'
          ? referencePrefix(address, pattern.body)
          : pattern.mode === 'suffix'
            ? referenceSuffix(address, pattern.body)
            : Math.min(
                referencePrefix(address, pattern.body),
                referenceSuffix(address, pattern.body),
              );
      assert.equal(pattern.score(bytes), expected, `${raw} vs ${address}`);
    }
  }
});

test('score ignores the spare byte past the address', () => {
  const base = crypto.randomBytes(35);
  const padded = Buffer.concat([base, Buffer.from([0xab])]);
  for (const raw of ['^a', 'abid$', 'ayd$']) {
    const pattern = parsePattern(raw);
    assert.equal(pattern.score(base), pattern.score(padded), raw);
  }
});

function referencePrefix(address, body) {
  let i = 0;
  while (i < body.length && address[i] === body[i]) i += 1;
  return i;
}

function referenceSuffix(address, body) {
  let i = 0;
  while (i < body.length && address[address.length - 1 - i] === body[body.length - 1 - i]) i += 1;
  return i;
}

test('no-tail patterns match against the bare public key', () => {
  const pattern = parsePattern('^ab');
  assert.equal(pattern.needsTail, false);
  for (let i = 0; i < 300; i += 1) {
    const publicKey = crypto.randomBytes(32);
    assert.equal(pattern.match(publicKey), base32Encode(publicKey).startsWith('ab'));
  }

  // 52 characters reach into the first checksum byte.
  assert.equal(parsePattern(`^${'a'.repeat(52)}`).needsTail, true);
  // 51 characters still fit inside the public key.
  assert.equal(parsePattern(`^${'a'.repeat(51)}`).needsTail, false);
});

test('score counts matching characters from the pattern side', () => {
  const zeros = Buffer.alloc(35); // encodes to 56 "a" characters
  assert.equal(parsePattern('^a').score(zeros), 1);
  assert.equal(parsePattern('^aa').score(zeros), 2);
  assert.equal(parsePattern('^ab').score(zeros), 1);
  assert.equal(parsePattern('ad$').score(zeros), 0);

  // Craft an address whose tail is a real one: characters 53..55 = "ayd".
  const versioned = Buffer.alloc(35);
  versioned[33] = 0x03; // checksum bits -> second-to-last character "y"
  versioned[34] = 0x03; // fixed version byte -> last character "d"
  const address = base32Encode(versioned);
  assert.ok(address.endsWith('ayd'), address);

  assert.equal(parsePattern('ad$').score(versioned), 1);
  assert.equal(parsePattern('yd$').score(versioned), 2);
  assert.equal(parsePattern('ayd$').score(versioned), 3);
  assert.ok(parsePattern('ayd$').match(versioned));
});
