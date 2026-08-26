import { Repo, type PeerId } from '@automerge/automerge-repo'
import { NodeWSServerAdapter } from '@automerge/automerge-repo-network-websocket'
import { NodeFSStorageAdapter } from '@automerge/automerge-repo-storage-nodefs'
import {
  Team,
  createServer,
  redactServer,
  type Keyring,
  type Server,
  type ServerWithSecrets,
} from '@localfirst/auth'
import { AuthProvider, getShareId, type ShareId } from '@localfirst/auth-provider-automerge-repo'
import { debug } from '@localfirst/shared'
import bodyParser from 'body-parser'
import chalk from 'chalk'
import cors from 'cors'
import express, { type ErrorRequestHandler } from 'express'
import fs from 'fs'
import { type Server as HttpServer } from 'http'
import { fileURLToPath } from 'url'
import path from 'path'
import { WebSocketServer } from 'ws'

const _dirname = path.dirname(fileURLToPath(import.meta.url))
const isDev = process.env.NODE_ENV === 'development'
const running = fs.readFileSync(path.join(_dirname, 'running.html'), 'utf8')

/**
 * This is a sync server for use with automerge-repo and the AuthProvider.
 *
 * The intended workflow for a client application is:
 * - Create a team
 * - GET `/keys` to obtain the server's public keys
 * - Add the server with its public keys to the team
 * - POST to `/teams` to send the team graph and keys to the server
 *
 * At this point anyone on the team can use automerge-repo with a AuthProvider to
 * authenticate with the server.
 */
export class LocalFirstAuthSyncServer {
  webSocketServer: WebSocketServer
  server: HttpServer
  storageDir: string

  /** What we hand out at `/keys`: everything a team needs to register us as a server. */
  publicServer: Server

  log = debug.extend('auth:syncserver')

  constructor(
    /**
     * A unique name for this server - probably its domain name or IP address. This should match the
     * name added to the localfirst/auth team.
     */
    private readonly host: string
  ) {
    this.log.extend(host)
  }

  async listen(
    options: {
      port?: number
      storageDir?: string
      silent?: boolean
    } = {}
  ) {
    return new Promise<void>(resolve => {
      const { port = 3000, storageDir = 'automerge-repo-data', silent = false } = options
      this.storageDir = storageDir

      if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir)

      // Get our identity from storage or create a new one
      const server = this.#getServer()
      this.publicServer = redactServer(server)

      // localfirst/auth will use this to send and receive authentication messages, and Automerge Repo will use it to send and receive sync messages
      this.webSocketServer = new WebSocketServer({ noServer: true })

      this.webSocketServer.on('close', (payload: any) => {
        this.close(payload)
      })

      // Set up the auth provider. A server is not a device: it signs links and answers identity
      // challenges as itself, using keys that never rotate.
      const peerId = this.host as PeerId
      const storage = new NodeFSStorageAdapter(storageDir)
      const auth = new AuthProvider({ serverIdentity: server, storage })

      // Set up the repo
      const adapter = new NodeWSServerAdapter(this.webSocketServer)
      const _repo = new Repo({
        peerId,
        // Use the auth provider to wrap our network adapter
        network: [auth.wrap(adapter)],
        // Use the same storage that the auth provider uses
        storage,
        // Since this is a server, we don't share generously — meaning we only sync documents they
        // already know about and can ask for by ID.
        sharePolicy: async _peerId => false,
      })

      // Set up the server
      const confirmation = `🤖 Sync server for Automerge Repo + @localfirst/auth running`

      const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
        console.error(err.stack)
        res.status(500).send(err.message)
      }

      this.server = express()
        // parse application/json
        .use(bodyParser.json())

        // enable CORS
        // TODO: allow providing custom CORS config
        .use(cors())

        /** So you can visit the sync server in a browser to get confirmation that it's running */
        .get('/', (req, res) => {
          res.send(running)
        })

        /** Endpoint to request the server's public record: its id and both of its keysets. */
        .get('/keys', (req, res) => {
          this.log('GET /keys %o', req.body)
          res.send(this.publicServer)
        })

        /** Endpoint to register a team. */
        .post('/teams', async (req, res) => {
          this.log('POST /teams %o', req.body)
          const { serializedGraph, teamKeyring } = req.body as {
            serializedGraph: Uint8Array
            teamKeyring: Keyring
          }

          // rehydrate the team using the serialized graph and the keys passed in the request
          const team = new Team({
            source: objectToUint8Array(serializedGraph),
            context: { server },
            teamKeyring,
          })

          if (auth.hasTeam(getShareId(team))) {
            res.status(500).send(`Team ${team.id} already registered`)
          }

          // add the team to our auth provider
          await auth.addTeam(team)
          res.end()
        })

        .post('/public-shares', async (req, res) => {
          this.log('POST /public-shares %o', req.body)
          const { shareId } = req.body as {
            shareId: ShareId
          }
          await auth.joinPublicShare(shareId)
          res.end()
        })

        .use(errorHandler)

        .listen(port, () => {
          if (!silent) {
            const hostExt = this.host + (port ? `:${port}` : '')
            const wsUrl = `${isDev ? 'ws' : 'wss'}://${hostExt}`
            const httpUrl = `${isDev ? 'http' : 'https'}://${hostExt}`
            console.log(
              [
                ``,
                `${chalk.yellow(confirmation)}`,
                `  ${chalk.green('➜')}  ${chalk.cyan(wsUrl)}`,
                `  ${chalk.green('➜')}  ${chalk.cyan(httpUrl)}`,
                ``,
              ].join('\n')
            )
          }
          resolve()
        })

      /**
       * When we successfully upgrade the client to a WebSocket connection, we emit a "connection"
       * event, which is handled by the NodeWSServerAdapter.
       */
      this.server.on('upgrade', (request, socket, head) => {
        this.webSocketServer.handleUpgrade(request, socket, head, socket => {
          this.webSocketServer.emit('connection', socket, request)
        })
      })
    })
  }

  close(payload?: any) {
    this.log('socket closed %o', payload)
    this.server.close()
  }

  /**
   * Loads our identity from storage, or mints one on first run. `serverId` is the fingerprint of
   * the identity keys, so this file *is* our name on every team we belong to: lose it and we're a
   * different server that has to be re-registered.
   */
  readonly #getServer = (): ServerWithSecrets => {
    const serverPath = path.join(this.storageDir, '__SERVER_IDENTITY.json')
    if (fs.existsSync(serverPath)) {
      // retrieve from storage
      return JSON.parse(fs.readFileSync(serverPath, 'utf8')) as ServerWithSecrets
    }

    // create & store a new identity
    const server = createServer({ host: this.host })
    fs.writeFileSync(serverPath, JSON.stringify(server, null, 2))
    return server
  }
}

/**
 *
 */
function objectToUint8Array(obj: Record<number, number>): Uint8Array {
  const arr = Object.values(obj)
  return new Uint8Array(arr)
}
