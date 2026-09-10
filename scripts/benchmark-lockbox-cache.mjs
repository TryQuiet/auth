// Build the auth package first. Compare two built checkouts by passing their auth/dist/index.js.
// Example: node scripts/benchmark-lockbox-cache.mjs ./packages/auth/dist/index.js
import { performance } from 'node:perf_hooks'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const auth = await import(pathToFileURL(resolve(process.argv[2] ?? 'packages/auth/dist/index.js')))
const firstDevice = auth.createFirstUseDevice({
  deviceName: 'benchmark',
  seed: 'lockbox-cache-benchmark-device-seed',
})
const userId = auth.deriveUserId(firstDevice.deviceId)
const user = auth.createUser('benchmark', userId, 'lockbox-cache-benchmark-user-seed')
const device = { ...firstDevice, userId }
const team = auth.createTeam('benchmark', { user, device }, 'lockbox-cache-benchmark-team-seed')
team.addRole('MEMBER')
team.addMemberRole(userId, 'MEMBER')
for (let i = 0; i < 8; i++) team.addRole(`channel-${i}`)

const message = { id: 'benchmark-hi', message: 'Hi', channelId: 'general' }
const encrypted = team.encrypt(message, 'MEMBER')
const samples = 5
const iterations = 100
const measure = operation => {
  for (let i = 0; i < 20; i++) operation()
  const timings = []
  for (let sample = 0; sample < samples; sample++) {
    const start = performance.now()
    for (let i = 0; i < iterations; i++) operation()
    timings.push((performance.now() - start) / iterations)
  }
  return Number(timings.sort((a, b) => a - b)[Math.floor(samples / 2)].toFixed(4))
}

console.log(
  JSON.stringify(
    {
      node: process.version,
      lockboxes: team.state.lockboxes.length,
      samples,
      iterations,
      medianMsPerOperation: {
        encrypt: measure(() => team.encrypt(message, 'MEMBER')),
        decrypt: measure(() => team.decrypt(encrypted)),
        readEightMessages: measure(() => {
          for (let i = 0; i < 8; i++) team.decrypt(encrypted)
        }),
      },
    },
    null,
    2
  )
)
