/**
 * Public programmatic API.
 *
 * @example
 * import { parsePattern, search } from 'onionaddress';
 *
 * const pattern = parsePattern('^abc');
 * const result = await search({ pattern, count: 1, workers: 4 });
 * console.log(result.found);
 */
export { benchmark } from './benchmark.js';
export {
  attemptsForProbability,
  difficulty,
  formatCount,
  formatDuration,
  formatInteger,
  formatProbability,
  successProbability,
} from './estimator.js';
export {
  ADDRESS_BYTES,
  ADDRESS_LENGTH,
  BASE32_ALPHABET,
  CHECKSUM_BYTES,
  HOSTNAME_LENGTH,
  ONION_SUFFIX,
  PUBLIC_KEY_BYTES,
  VERSION_BYTE,
  addressBytesForPublicKey,
  addressFromPrivateKey,
  addressFromPublicKey,
  addressFromPublicKeyBytes,
  base32Encode,
  checksumForPublicKey,
  generateKeyPair,
  hostnameFromAddress,
  privateKeyFromSeed,
  publicKeyBytes,
  publicKeyFileBytes,
  secretKeyFileBytes,
  seedFromPrivateKey,
} from './onion.js';
export { benchmarkMiner, findMiner, listMinerDevices, verifyMinerMatch } from './gpu.js';
export { ensureOutputDir, saveResult } from './output.js';
export { PatternError, parsePattern } from './pattern.js';
export { defaultWorkerCount, search } from './search.js';
export { VERSION } from './version.js';
