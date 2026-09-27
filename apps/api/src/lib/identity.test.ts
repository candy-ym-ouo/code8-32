import { describe, expect, it } from 'vitest';
import { normalizeEmail } from './identity.js';

describe('normalizeEmail', () => {
  it('produces one key for case, whitespace and unicode-form variants', () => {
    const base = normalizeEmail('user@example.com');
    expect(normalizeEmail('User@Example.com')).toBe(base);
    expect(normalizeEmail('  user@example.com  ')).toBe(base);
    expect(normalizeEmail('USER@EXAMPLE.COM')).toBe(base);
    // NFC 与 NFD 形态必须归一到同一账号键
    expect(normalizeEmail('café@example.com')).toBe(normalizeEmail('café@example.com'));
  });

  it('keeps distinct accounts distinct', () => {
    expect(normalizeEmail('a@example.com')).not.toBe(normalizeEmail('b@example.com'));
  });
});
