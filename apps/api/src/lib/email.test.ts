import { describe, expect, it } from 'vitest';
import { normalizeEmail } from './email.js';

describe('normalizeEmail', () => {
  it('maps case, whitespace and unicode variants to the same account key', () => {
    const key = normalizeEmail('user@example.com');
    expect(normalizeEmail('User@Example.com')).toBe(key);
    expect(normalizeEmail('  user@example.com')).toBe(key);
    expect(normalizeEmail('user@example.com  ')).toBe(key);
    expect(normalizeEmail('USER@EXAMPLE.COM')).toBe(key);
  });

  it('unifies NFC and NFD unicode forms so deformation cannot split quota buckets', () => {
    const nfc = normalizeEmail('café@example.com'.normalize('NFC'));
    const nfd = normalizeEmail('café@example.com'.normalize('NFD'));
    expect(nfd).toBe(nfc);
  });
});
