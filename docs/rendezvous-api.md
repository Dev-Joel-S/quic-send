# Rendezvous API, version 1

This is what a quic-send rendezvous server has to do. Two implementations exist and are
held to it by the same tests: the Rust server in `qs-rendezvous/` and the Cloudflare Worker
in `rendezvous-worker/`. A client does not need to know which one it talks to.

The Rust types for everything below are in `qs-rendezvous-api/`.

## What the server is

An untrusted mailbox. Two peers that share a short code pass three opaque messages through
one slot. The server never looks into a message and holds no secrets. The clients are built
so that a hostile server can deny service and nothing else: it cannot read what is exchanged
and cannot put itself between the two peers.

A code like `K7X4-M2QP` has two parts. The first two characters are the **nameplate**. It
names the slot, the server picks it and everybody may know it. The other six are a secret
the server never sees.

## Conventions

- The base url is whatever the user configured, for example `https://rz.example.com`. All
  paths below are appended to it.
- Request and response bodies are JSON (`Content-Type: application/json`). A receiver of
  JSON ignores members it does not know.
- A binary message is a string of base64, url safe alphabet, without padding.
- A message is at most 16384 bytes before base64. A slot stores three of them.
- A nameplate is two characters of `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (Crockford Base32,
  upper case). That makes 1024 nameplates.
- A token is a string the server makes up, at least 128 bits from a cryptographic random
  number generator. A client sends it back as `Authorization: Bearer <token>`. The server
  compares tokens in constant time.
- The server does not follow or send redirects. Clients do not follow them.

## Version

`GET /v1`

```json
{ "service": "quic-send-rendezvous", "api": 1 }
```

A client asks this first. It does not use a server whose `service` is another one or whose
`api` is not the version it speaks. The path prefix `/v1` and `api` change together, and
only for a change that an old client or server would get wrong. Additions that both sides
can ignore (a new member in an answer, a new error code for a new situation) do not change
the version.

## The exchange

| Step | Request | Sent by | Token | Purpose |
|------|---------|---------|-------|---------|
| 1 | `POST /v1/slots` | sender | none | open a slot with the first message |
| 2 | `GET /v1/slots/{nameplate}` | receiver | none | read the first message |
| 3 | `PUT /v1/slots/{nameplate}/reply` | receiver | none | store the reply |
| 4 | `GET /v1/slots/{nameplate}/reply` | sender | sender's | wait for the reply |
| 5 | `PUT /v1/slots/{nameplate}/address` | sender | sender's | store the sealed address |
| 6 | `GET /v1/slots/{nameplate}/address` | receiver | receiver's | wait for the address |
| any time | `DELETE /v1/slots/{nameplate}` | either | its own | give up |

### 1. Open a slot

`POST /v1/slots` with `{ "message": "<base64>" }`

`201 Created`

```json
{ "nameplate": "K7", "token": "<sender token>", "expires_in": 300 }
```

The server picks a nameplate that is free, at random. It never hands out a nameplate that
is in use. It should prefer one that was not in use recently, so a late request for a slot
that ended does not meet a new one. `expires_in` is the number of seconds the slot lives if
no reply arrives.

`503 no_free_slot` if no nameplate is free. A server may also answer this while a few
nameplates are still free, if it gives up looking for one.

### 2. Look at a slot

`GET /v1/slots/{nameplate}`

`200 OK` with `{ "message": "<the first message>" }`

This request **changes nothing**. It needs no token, can be repeated any number of times by
anybody, does not count as an attempt at the code and does not extend the life of the slot.
The first message is a key exchange message and a public key, which give nothing away.

Once the slot has its reply, the answer is `409 slot_used`.

### 3. Reply

`PUT /v1/slots/{nameplate}/reply` with `{ "message": "<base64>" }`

`200 OK`

```json
{ "token": "<receiver token>", "expires_in": 120 }
```

A slot takes **exactly one reply**. The first one is stored, every later one gets
`409 slot_used` and changes nothing. This is the rule the security of the short code rests
on: the reply is the one guess at the secret that the sender checks.

With the reply the slot gets more time, `expires_in` says how much is left. The life of a
slot is never shortened by a reply.

### 4. Wait for the reply

`GET /v1/slots/{nameplate}/reply?wait=<seconds>` with the sender's token

`200 OK` with `{ "message": "<the reply>" }`, or `204 No Content` if there is none yet.

### 5. Store the address

`PUT /v1/slots/{nameplate}/address` with `{ "message": "<base64>" }` and the sender's token

`204 No Content`

Only after the reply, and only once. Otherwise `400 bad_request`.

### 6. Wait for the address

`GET /v1/slots/{nameplate}/address?wait=<seconds>` with the receiver's token

`200 OK` with `{ "message": "<the address>" }`, or `204 No Content` if there is none yet.

The address is delivered once. With that answer the slot has ended as `used`.

### Giving up

`DELETE /v1/slots/{nameplate}` with the token of either side

`204 No Content`. The slot has ended as `closed`. Deleting a slot that does not exist any
more is `204` as well, with any token.

## Waiting

`wait` is the number of seconds the server may hold the request until the message is there.
Without it, or with `0`, the answer is immediate. The server answers as soon as the message
arrives. It may wait for less than was asked, and never waits longer than 25 seconds. A
client that gets `204` asks again, but not more often than once per second.

A request that is waiting when the slot ends gets the error for that end (`slot_expired`,
`slot_closed`) right then, not only when it asks the next time.

## The life of a slot

A slot ends when

- the address was delivered (`used`),
- either side deleted it (`closed`),
- its time ran out (`expired`). The time is 300 seconds from step 1 by default, and at
  least 120 seconds from step 3. An operator may choose other values.

The server remembers for a while (ten minutes by default) how a slot ended, and answers
requests for it with `slot_used`, `slot_closed` or `slot_expired` instead of `unknown_slot`.
When the nameplate is handed out again, that memory is gone.

## Errors

An error answer has a fitting HTTP status and the body `{ "error": "<code>" }`.

| Code | Status | Meaning |
|------|--------|---------|
| `unknown_slot` | 404 | no slot with this nameplate, and none that ended recently. Also for a nameplate that is not well formed |
| `slot_used` | 409 | the slot has its reply, or was completed |
| `slot_expired` | 410 | the time of the slot ran out |
| `slot_closed` | 410 | one side gave up |
| `forbidden` | 403 | the token is missing, wrong, or the one of the other side |
| `too_large` | 413 | the message is larger than 16384 bytes |
| `no_free_slot` | 503 | no nameplate is free |
| `rate_limited` | 429 | too many requests from this address |
| `bad_request` | 400 | the body cannot be read, or the request makes no sense at this point |

A request whose body is far larger than a message may be refused with any `4xx` status
before it is read.

## Limits

A server may limit requests per client address and answer `429 rate_limited`. It should
limit steps 1 and 3. A limit on step 2 has to be counted on its own: looking at slots must
never use up what a client needs for step 3, and never changes a slot.

A server should not write nameplates into its logs next to client addresses.

## Checking an implementation

The tests in `qs-rendezvous/tests/server.rs` run against any server:

```
QS_RENDEZVOUS_URL=http://127.0.0.1:8787 \
QS_RENDEZVOUS_QUICK_URL=http://127.0.0.1:8788 \
cargo test -p qs-rendezvous --test server -- --test-threads=1
```

`QS_RENDEZVOUS_URL` is an instance with its limits wide open. `QS_RENDEZVOUS_QUICK_URL` is
optional, an instance where a slot expires after one second without a reply and lives for a
minute with one. `rendezvous-worker/test.sh` does this for the Worker.
