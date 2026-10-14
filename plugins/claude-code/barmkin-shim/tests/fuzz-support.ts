// Seeded helpers shared by the fuzz tests. Not a test file itself.

// mulberry32: a small seeded PRNG with a full 32-bit state, so a failing trial
// can be replayed from its seed and index.
export function rng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export interface Rand {
  next: () => number
  int: (lo: number, hi: number) => number
  pick: <T>(items: readonly T[]) => T
  chars: (alphabet: string, n: number) => string
}

export function randOf(seed: number): Rand {
  const next = rng(seed)
  const int = (lo: number, hi: number): number => lo + Math.floor(next() * (hi - lo + 1))
  return {
    next,
    int,
    pick: (items) => items[int(0, items.length - 1)],
    chars: (alphabet, n) => {
      let out = ''
      for (let i = 0; i < n; i++) out += alphabet[int(0, alphabet.length - 1)]
      return out
    },
  }
}

// A PEM private-key header, built from pieces: written out in full it is what a
// secret scanner flags in a source file, even one that is a test fixture.
export const pemHeader = (kind: 'BEGIN' | 'END', algo = ''): string => '-----' + kind + ' ' + algo + 'PRIVATE ' + 'KEY-----'

export const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
export const UPPER_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
export const B64 = ALNUM + '+/'

// The shapes that cost the most: runs the four expensive rules rescan from
// every start, and ordinary text that merely mentions their keywords.
export function worstInputs(size: number): Record<string, string> {
  const fill = (unit: string) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size)
  return {
    'SECRET= run': fill('SECRET='),
    'eyJ- run': fill('eyJ-'),
    'eyJ.a. then hyphens': 'eyJ-'.repeat(size / 8) + 'eyJ.a.' + '-'.repeat(size / 2 - 6),
    'PEM BEGIN lines': fill('-----BEGIN PRIVATE KEY-----\n'),
    'PEM END lines': fill('-----END PRIVATE KEY-----\n'),
    'Bearer run': fill('Bearer abcdefghijklmnopqrst'),
    'Bearer then spaces': 'Bearer ' + ' '.repeat(size - 7),
    'quoted value no close': fill("X_TOKEN='aaaa1"),
    'name spaces': fill('A_TOKEN \t'),
    'realistic prose': fill('const token = refreshedAccessTokenValue; // Bearer of bad news, key=value\n'),
  }
}
