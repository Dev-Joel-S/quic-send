# Rendezvous server as a Cloudflare Worker

The rendezvous server of quic-send, for people who do not want to run a machine for it.
It does the same as the Rust server in [`qs-rendezvous`](../qs-rendezvous): both implement
[docs/rendezvous-api.md](../docs/rendezvous-api.md), and the same tests run against both.
A client cannot tell them apart, and you can move from one to the other by changing the
url in the config file.

Each nameplate (the first two characters of a code) has its own Durable Object that keeps
the slot of that code. Nothing is shared between slots, nothing is logged, and the Worker
holds no secrets. Like every rendezvous server it is not trusted by the clients: it can
make a pairing fail, it cannot read or redirect one.

All the code that runs is [`src/index.js`](src/index.js), without dependencies or a build
step.

## Deploy

You need a Cloudflare account and Node.js.

```
cd rendezvous-worker
npm ci
npx wrangler login
npx wrangler deploy
```

`wrangler deploy` prints the url of the Worker, something like
`https://quic-send-rendezvous.<your-subdomain>.workers.dev`. Put it into the config file
of quic-send on both computers (`qsend config` shows where that file is):

```toml
rendezvous = ["https://quic-send-rendezvous.<your-subdomain>.workers.dev"]
```

No server address is built into quic-send, so this step is not optional. Several servers
can be listed, they are tried in order.

## Settings

In [`wrangler.toml`](wrangler.toml):

| Setting | Default | Meaning |
|---------|---------|---------|
| `TTL_SECS` | 300 | seconds a code stays valid while nobody has replied to it |
| `REPLY_TTL_SECS` | 120 | seconds the two peers have to finish once the reply is there |
| `REMEMBER_SECS` | 600 | seconds an ended slot is remembered, to tell a client why it is gone |
| `MAX_WAIT_SECS` | 25 | longest a request waits for a message |
| `CREATE_LIMIT` | 30 per minute | slots one address may open |
| `REPLY_LIMIT` | 30 per minute | replies one address may send. A reply is a guess at a code |
| `LOOK_LIMIT` | 120 per minute | looks at a slot one address may take. They cost the slot nothing |

The three limits are rate limit bindings. Their `namespace_id` only has to be a number that
no other rate limit on your account uses.

A sender that waits for its receiver keeps a request open, and that keeps the Durable Object
of its slot running. Cloudflare bills Durable Objects by the time they run, so a smaller
`MAX_WAIT_SECS` costs less and makes the clients ask more often. Look at Cloudflare's
current pricing for Workers and Durable Objects before you open the server to many users.

## Test

```
./test.sh
```

starts the Worker on this computer with `wrangler dev` and runs the tests of the repository
against it. Nothing is deployed and no account is needed. It needs the Rust toolchain,
because the tests are the ones of the Rust server.
