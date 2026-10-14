/**
 * Difficulty estimation for a uniform search space.
 *
 * v3 addresses carry at most 280 bits of entropy (PUBKEY | CHECKSUM |
 * VERSION); the fixed version byte removes 8 of them, which the pattern
 * compiler already accounts for. Whatever bits a pattern pins down are
 * uniform, so the number of attempts until a match follows a geometric
 * distribution with p = 1/space:
 *
 *   P(found within t attempts) = 1 - (1 - p)^t ~= 1 - e^(-t / space)
 *   expected attempts          = 1 / p = space
 *   median attempts            = ln(2)   * space
 *   p90 attempts               = ln(10)  * space
 *   p99 attempts               = ln(100) * space
 *
 * Because the distribution is memoryless, the expected number of *remaining*
 * attempts never goes down while searching: the estimator is what lets you
 * pick a feasible target before burning CPU time.
 */

const COMPACT = new Intl.NumberFormat('en-US', {
  notation: 'compact',
  maximumSignificantDigits: 3,
});
const GROUPED = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

export function difficulty(space) {
  return Object.freeze({
    space,
    expectedAttempts: space,
    medianAttempts: space * Math.LN2,
    p90Attempts: space * Math.LN10,
    p99Attempts: space * Math.log(100),
  });
}

/**
 * Cumulative probability of having found a match after `attempts` tries.
 */
export function successProbability(attempts, space) {
  if (!(space > 0)) return 1;
  if (space === 1) return attempts >= 1 ? 1 : 0; // e.g. a "d$" suffix always matches
  return -Math.expm1(-attempts / space);
}

/**
 * Number of attempts that give the requested cumulative success probability.
 */
export function attemptsForProbability(probability, space) {
  return -Math.log1p(-probability) * space;
}

export function formatCount(value) {
  if (!Number.isFinite(value)) return '∞';
  if (Math.abs(value) >= 10000) return COMPACT.format(value);
  return GROUPED.format(value);
}

export function formatInteger(value) {
  if (!Number.isFinite(value)) return '∞';
  if (Math.abs(value) >= 1e15) return value.toExponential(3);
  return GROUPED.format(value);
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '∞';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(1)}m`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  const days = hours / 24;
  if (days < 365) return `${days.toFixed(1)}d`;
  return `${(days / 365).toFixed(1)}y`;
}

export function formatProbability(probability) {
  if (!(probability > 0)) return '0%';
  if (probability >= 1) return '100%';
  const percent = probability * 100;
  if (percent < 0.01) return `${percent.toExponential(1)}%`;
  return `${percent.toFixed(2)}%`;
}
