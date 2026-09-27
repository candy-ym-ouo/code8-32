import { describe, expect, it } from 'vitest';
import { isAttemptBlocked, minutesInterval } from './throttle-policy.js';

describe('isAttemptBlocked', () => {
  const now = new Date('2026-09-26T12:00:00.000Z');

  it('allows attempts up to the failure quota and blocks beyond it', () => {
    expect(isAttemptBlocked(1, null, 5, now)).toBe(false);
    expect(isAttemptBlocked(5, null, 5, now)).toBe(false);
    expect(isAttemptBlocked(6, null, 5, now)).toBe(true);
  });

  it('blocks while the lock is active regardless of count', () => {
    const lockedUntil = new Date('2026-09-26T12:15:00.000Z');
    expect(isAttemptBlocked(1, lockedUntil, 5, now)).toBe(true);
  });

  it('allows again once the lock has expired', () => {
    const expiredLock = new Date('2026-09-26T11:59:59.000Z');
    expect(isAttemptBlocked(1, expiredLock, 5, now)).toBe(false);
  });
});

describe('minutesInterval', () => {
  it('renders a postgres interval literal', () => {
    expect(minutesInterval(15)).toBe('15 minutes');
  });
});
