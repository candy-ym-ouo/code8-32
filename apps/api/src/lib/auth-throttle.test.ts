import { describe, expect, it } from 'vitest';
import {
  activeLockUntil,
  applyFailure,
  loginSubjectKey,
  userSubjectKey,
  type ThrottleConfig,
  type ThrottleState
} from './auth-throttle.js';

const config: ThrottleConfig = { maxFailures: 5, windowMs: 15 * 60 * 1000, lockMs: 15 * 60 * 1000 };
const t0 = new Date('2026-09-26T12:00:00.000Z');

function freshState(): ThrottleState {
  return { failures: 0, windowStartAt: t0, lockedUntil: null };
}

describe('loginSubjectKey / userSubjectKey', () => {
  it('derives the login key from the normalized email, not the raw input', () => {
    const key = loginSubjectKey(' User@Example.com ');
    expect(key).toBe('login:user@example.com');
    expect(loginSubjectKey('USER@example.com')).toBe(key);
    expect(loginSubjectKey('user@example.com')).toBe(key);
  });

  it('scopes password verification to the user id', () => {
    expect(userSubjectKey('00000000-0000-0000-0000-000000000001')).toBe(
      'user:00000000-0000-0000-0000-000000000001'
    );
  });
});

describe('activeLockUntil', () => {
  it('reports only locks that are still in the future', () => {
    const future = new Date(t0.getTime() + 60_000);
    const past = new Date(t0.getTime() - 60_000);
    expect(activeLockUntil({ lockedUntil: future }, t0)).toEqual(future);
    expect(activeLockUntil({ lockedUntil: past }, t0)).toBeNull();
    expect(activeLockUntil({ lockedUntil: null }, t0)).toBeNull();
  });
});

describe('applyFailure', () => {
  it('counts failures within the window and locks at the threshold', () => {
    let state = freshState();
    for (let i = 1; i < config.maxFailures; i += 1) {
      const at = new Date(t0.getTime() + i * 1000);
      const { next, verdict } = applyFailure(state, at, config);
      expect(verdict).toEqual({ kind: 'failed', failures: i });
      state = next;
    }
    const at = new Date(t0.getTime() + config.maxFailures * 1000);
    const { next, verdict } = applyFailure(state, at, config);
    expect(verdict.kind).toBe('locked');
    if (verdict.kind === 'locked') {
      expect(verdict.lockedUntil.getTime()).toBe(at.getTime() + config.lockMs);
    }
    expect(next.failures).toBe(0);
    expect(next.lockedUntil).not.toBeNull();
  });

  it('resets the count when the window has expired', () => {
    const state: ThrottleState = { failures: 4, windowStartAt: t0, lockedUntil: null };
    const later = new Date(t0.getTime() + config.windowMs + 1000);
    const { next, verdict } = applyFailure(state, later, config);
    expect(verdict).toEqual({ kind: 'failed', failures: 1 });
    expect(next.windowStartAt).toEqual(later);
  });

  it('keeps an active lock instead of counting further failures', () => {
    const lockedUntil = new Date(t0.getTime() + config.lockMs);
    const state: ThrottleState = { failures: 0, windowStartAt: t0, lockedUntil };
    const during = new Date(t0.getTime() + 60_000);
    const { next, verdict } = applyFailure(state, during, config);
    expect(verdict).toEqual({ kind: 'locked', lockedUntil });
    expect(next).toBe(state);
  });

  it('counts again after the lock has expired', () => {
    const lockedUntil = new Date(t0.getTime() + config.lockMs);
    const state: ThrottleState = { failures: 0, windowStartAt: t0, lockedUntil };
    const after = new Date(lockedUntil.getTime() + 1000);
    const { verdict } = applyFailure(state, after, config);
    expect(verdict).toEqual({ kind: 'failed', failures: 1 });
  });

  it('serializes concurrent bursts: the Nth sequential failure locks regardless of timing', () => {
    // 并发请求由行锁串行化后逐个进入状态机；模拟同一毫秒内连续到达。
    let state = freshState();
    const results: string[] = [];
    for (let i = 0; i < config.maxFailures + 3; i += 1) {
      const { next, verdict } = applyFailure(state, t0, config);
      results.push(verdict.kind);
      state = next;
    }
    expect(results).toEqual([
      ...Array<string>(config.maxFailures - 1).fill('failed'),
      'locked',
      'locked',
      'locked',
      'locked'
    ]);
  });
});
