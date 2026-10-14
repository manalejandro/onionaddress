import assert from 'node:assert/strict';
import test from 'node:test';
import {
  attemptsForProbability,
  difficulty,
  formatCount,
  formatDuration,
  formatInteger,
  formatProbability,
  successProbability,
} from '../src/estimator.js';

test('difficulty matches the geometric distribution', () => {
  const stats = difficulty(32768);
  assert.equal(stats.expectedAttempts, 32768);
  assert.equal(stats.medianAttempts, 32768 * Math.LN2);
  assert.equal(stats.p90Attempts, 32768 * Math.LN10);
  assert.equal(stats.p99Attempts, 32768 * Math.log(100));
});

test('successProbability approaches 1 - e^-1 at the expected effort', () => {
  const probability = successProbability(1024, 1024);
  assert.ok(Math.abs(probability - (1 - Math.E ** -1)) < 1e-9);
  assert.equal(successProbability(0, 1024), 0);
});

test('successProbability handles a unit search space', () => {
  // e.g. a "d$" suffix: the very first candidate matches.
  assert.equal(successProbability(0, 1), 0);
  assert.equal(successProbability(1, 1), 1);
});

test('attemptsForProbability inverts successProbability', () => {
  const attempts = attemptsForProbability(0.9, 32768);
  assert.ok(Math.abs(successProbability(attempts, 32768) - 0.9) < 1e-9);
});

test('formatters produce human-readable values', () => {
  assert.equal(formatCount(1234), '1,234');
  assert.equal(formatCount(1_500_000), '1.5M');
  assert.equal(formatInteger(32768), '32,768');
  assert.equal(formatDuration(0.5), '500ms');
  assert.equal(formatDuration(90), '1.5m');
  assert.equal(formatDuration(7200), '2.0h');
  assert.equal(formatDuration(86400 * 3), '3.0d');
  assert.equal(formatProbability(0.5), '50.00%');
  assert.equal(formatProbability(0), '0%');
});
