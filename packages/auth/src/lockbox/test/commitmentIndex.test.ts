import { CommitmentIndex } from 'lockbox/commitmentIndex.js'
import { describe, expect, it } from 'vitest'

describe('persistent established-commitment index', () => {
  it('isolates branches and preserves each established generation', () => {
    const root = CommitmentIndex.empty.add('TEAM:0', 'original')
    const left = root.add('ROLE:member:0', 'left')
    const right = root.add('ROLE:member:0', 'right')
    expect(root.get('ROLE:member:0')).toBeUndefined()
    expect(left.get('ROLE:member:0')).toBe('left')
    expect(right.get('ROLE:member:0')).toBe('right')
    expect(left.add('TEAM:0', 'forged').get('TEAM:0')).toBe('original')
    expect(right.get('TEAM:0')).toBe('original')
  })

  it('does fixed input-length work for appends and lookups after 1,000 prior identities', () => {
    let index = CommitmentIndex.empty
    let charactersRead = 0
    // Count actual characters consumed by the running trie, not elapsed wall time or a model.
    const counted = (value: string) =>
      ({
        length: value.length,
        charCodeAt(offset: number) {
          charactersRead++
          return value.charCodeAt(offset) // eslint-disable-line unicorn/prefer-code-point -- Count UTF-16 trie steps.
        },
      }) as unknown as string
    for (let n = 0; n < 1000; n++) {
      const identity = `USER:${String(n).padStart(4, '0')}:0`
      const before = charactersRead
      index = index.add(counted(identity), `commitment-${n}`)
      expect(charactersRead - before).toBe(identity.length)
      const beforeRead = charactersRead
      expect(index.get(counted('USER:0000:0'))).toBe('commitment-0')
      expect(charactersRead - beforeRead).toBe('USER:0000:0'.length)
    }
    expect(index.get('USER:0999:0')).toBe('commitment-999')
  })

  it('keeps arbitrary Unicode names distinct without recursion or delimiter aliases', () => {
    const identities = ['', 'a', 'aa', 'a:b', 'a\u0000b', '🙃', '🔒', 'x'.repeat(10_000)]
    let index = CommitmentIndex.empty
    for (const identity of identities) index = index.add(identity, JSON.stringify(identity))
    for (const identity of identities) expect(index.get(identity)).toBe(JSON.stringify(identity))
  })
})
