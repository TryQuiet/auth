import { describe, expect, it } from 'vitest'
import { setup } from 'util/testing/index.js'

describe('missing key diagnostics', () => {
  it('does not expose any available secret when an untrusted envelope requests an unknown scope', () => {
    const { alice } = setup('alice')
    const secrets: string[] = []
    const visit = (value: unknown, field = '') => {
      if (typeof value === 'string' && field.includes('secretKey')) secrets.push(value)
      else if (value && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) visit(item, key)
      }
    }
    visit(alice.team.allKeys())
    expect(secrets.length).toBeGreaterThan(3)
    for (const read of [
      () => alice.team.roleKeys('unknown-role'),
      () => alice.team.roleKeysAllGenerations('unknown-role'),
    ]) {
      let error: unknown
      try {
        read()
      } catch (error_) {
        error = error_
      }
      expect(error).toBeInstanceOf(Error)
      const diagnostic = String((error as Error).stack)
      for (const secret of secrets) expect(diagnostic).not.toContain(secret)
      expect(diagnostic).not.toContain('Keymap')
      expect(diagnostic).not.toContain('lockboxes')
    }
  })
})
