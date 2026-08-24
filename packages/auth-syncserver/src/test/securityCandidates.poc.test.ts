import { createTeam } from '@localfirst/auth'
import { describe, expect, it } from 'vitest'
import { host, setup } from './helpers/setup.js'

describe('security candidate PoCs: sync-server registration', () => {
  it('accepts graph and keyring material before any compatibility handshake', async () => {
    const { users, url, teardown } = await setup(['alice'])

    try {
      const { alice } = users
      const team = createTeam('compatibility-poc', { user: alice.user, device: alice.device })
      const keysResponse = await fetch(`http://${url}/keys`)
      const serverRecord = await keysResponse.json()

      team.addServer({ ...serverRecord, host })

      // Registration is accepted directly over HTTP. No Auth.Connection REQUEST_IDENTITY or
      // protocol-version negotiation runs before the server receives the graph and keyring.
      const response = await fetch(`http://${url}/teams`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serializedGraph: team.save(),
          teamKeyring: team.teamKeyring(),
        }),
      })

      expect(response.status).toBe(200)
    } finally {
      teardown()
    }
  })
})
