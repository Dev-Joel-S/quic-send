// Rendezvous server for quic-send as a Cloudflare Worker.
//
// It implements docs/rendezvous-api.md, like the Rust server in qs-rendezvous/, and the
// same tests run against both (see test.sh).
//
// The Worker is an untrusted mailbox: it passes three opaque messages between two peers
// that share a short code, never looks into them and holds no secrets. Every nameplate
// (the first two characters of a code) has its own Durable Object, which keeps the slot.
// There is no state that is shared between slots.
//
// No dependencies, no build step: this file is all the code that runs.

import { DurableObject } from "cloudflare:workers";

const SERVICE_NAME = "quic-send-rendezvous";
const API_VERSION = 1;
// Crockford Base32, without I, L, O and U
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const NAMEPLATE = /^[0-9A-HJKMNP-TV-Z]{2}$/;
// Largest message a slot stores, before base64
const MAX_MESSAGE_BYTES = 16 * 1024;
// Largest request body that is read at all: base64 and JSON around a message, with room
const MAX_BODY_BYTES = MAX_MESSAGE_BYTES * 2;
// Longest a GET may wait for a message, in seconds
const MAX_WAIT_SECS = 25;
// How often a free nameplate is looked for before giving up. Every try is a request to
// a Durable Object, and a Worker may only make a limited number of those per request.
const TRIES_FRESH = 16;
const TRIES_ANY = 16;

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function empty() {
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

const STATUS = {
  unknown_slot: 404,
  slot_used: 409,
  slot_expired: 410,
  slot_closed: 410,
  forbidden: 403,
  too_large: 413,
  no_free_slot: 503,
  rate_limited: 429,
  bad_request: 400,
};

function error(code) {
  return json(STATUS[code], { error: code });
}

/** Turn what a slot answered into a response */
function answer(result) {
  if (result.error) return error(result.error);
  if (result.body === undefined) return empty();
  return json(result.status ?? 200, result.body);
}

/** A setting from the environment as a whole number of seconds, or the default */
function seconds(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function settings(env) {
  return {
    // How long a slot lives while nobody has replied to it
    ttl: seconds(env.TTL_SECS, 300) * 1000,
    // How long the two peers have to finish once the reply is there
    replyTtl: seconds(env.REPLY_TTL_SECS, 120) * 1000,
    // How long an ended slot is remembered, to tell why it is gone
    remember: seconds(env.REMEMBER_SECS, 600) * 1000,
    maxWait: Math.min(seconds(env.MAX_WAIT_SECS, MAX_WAIT_SECS), MAX_WAIT_SECS),
  };
}

/** A token nobody can guess: 128 random bits */
function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Compare two tokens without stopping at the first difference, so the time it takes
 * says nothing about how much of a guessed token was right
 */
function sameToken(expected, given) {
  if (typeof expected !== "string" || typeof given !== "string") return false;
  if (expected.length !== given.length) return false;
  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= expected.charCodeAt(i) ^ given.charCodeAt(i);
  }
  return difference === 0;
}

function randomNameplate() {
  // 32 characters: five bits of a random byte pick one without bias
  const bytes = crypto.getRandomValues(new Uint8Array(2));
  return ALPHABET[bytes[0] & 31] + ALPHABET[bytes[1] & 31];
}

/** The token of a request, or null */
function bearer(request) {
  const header = request.headers.get("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : null;
}

/**
 * The address a request is counted against. Cloudflare sets this header itself, a
 * client cannot. IPv6 addresses are counted per /64.
 */
function addressKey(request) {
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  if (!ip.includes(":")) return ip;

  const [head, tail] = ip.split("::");
  const front = head ? head.split(":") : [];
  const back = tail ? tail.split(":") : [];
  const missing = tail === undefined ? 0 : Math.max(0, 8 - front.length - back.length);
  const groups = [...front, ...Array(missing).fill("0"), ...back];
  return groups.slice(0, 4).join(":") + "::/64";
}

/**
 * Count a request against a limit, if the limit is configured. The limits are rate limit
 * bindings in wrangler.toml and can be left out.
 */
async function allowed(limiter, request) {
  if (!limiter) return true;
  const { success } = await limiter.limit({ key: addressKey(request) });
  return success;
}

/** Read a body of at most `limit` bytes. Returns null if it is larger. */
async function readBody(request, limit) {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > limit) return null;
  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/** The number of bytes `text` decodes to if it is base64 (url safe, no padding), else null */
function base64Bytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;

  let bytes;
  try {
    bytes = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  } catch {
    return null;
  }
  // Only the one way of writing these bytes is accepted, like the Rust server does
  const again = btoa(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  return again === text ? bytes.length : null;
}

/**
 * The message of a request body, still as base64: the server stores it as it came and
 * never looks inside. Returns { message } or { error }.
 */
async function readMessage(request) {
  const body = await readBody(request, MAX_BODY_BYTES);
  if (body === null) return { error: "too_large" };

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return { error: "bad_request" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "bad_request" };
  }
  if (typeof parsed.message !== "string") return { error: "bad_request" };

  const size = base64Bytes(parsed.message);
  if (size === null) return { error: "bad_request" };
  if (size > MAX_MESSAGE_BYTES) return { error: "too_large" };
  return { message: parsed.message };
}

/** Seconds to wait from the query of a request */
function waitSeconds(url) {
  const wait = Number(url.searchParams.get("wait") ?? 0);
  return Number.isFinite(wait) && wait > 0 ? wait : 0;
}

async function createSlot(request, env) {
  const { message, error: problem } = await readMessage(request);
  if (problem) return error(problem);
  if (!(await allowed(env.CREATE_LIMIT, request))) return error("rate_limited");

  // A random nameplate that is free. First one that was not used recently, so a late
  // request for an ended slot does not meet a new one, then any free one.
  for (let i = 0; i < TRIES_FRESH + TRIES_ANY; i++) {
    const nameplate = randomNameplate();
    const slot = env.SLOT.get(env.SLOT.idFromName(nameplate));
    const created = await slot.create(message, i < TRIES_FRESH);
    if (created) {
      return json(201, {
        nameplate,
        token: created.token,
        expires_in: created.expiresIn,
      });
    }
  }
  return error("no_free_slot");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter((part) => part !== "");
    const method = request.method;

    // Only the exact paths of the API, without empty parts or a slash at the end
    if (url.pathname !== "/" + parts.join("/")) return error("unknown_slot");
    if (parts[0] !== "v1" || parts.length > 4) return error("unknown_slot");

    if (parts.length === 1) {
      if (method !== "GET") return error("bad_request");
      return json(200, { service: SERVICE_NAME, api: API_VERSION });
    }
    if (parts[1] !== "slots") return error("unknown_slot");

    if (parts.length === 2) {
      if (method !== "POST") return error("bad_request");
      return createSlot(request, env);
    }

    // Everything below is about one slot. A name that is no nameplate never reaches a
    // Durable Object, so nobody can make the Worker create objects for made up names.
    const nameplate = parts[2];
    const what = parts[3];
    const slot = () => env.SLOT.get(env.SLOT.idFromName(nameplate));
    const known = NAMEPLATE.test(nameplate);

    if (what === undefined && method === "GET") {
      if (!(await allowed(env.LOOK_LIMIT, request))) return error("rate_limited");
      if (!known) return error("unknown_slot");
      return answer(await slot().look());
    }

    // The requests below need a token. Without one the answer is the same whatever
    // the slot is, like the Rust server gives it.
    const token = bearer(request);

    if (what === undefined && method === "DELETE") {
      if (token === null) return error("forbidden");
      if (!known) return empty();
      return answer(await slot().close(token));
    }

    if (what === "reply" && method === "PUT") {
      const { message, error: problem } = await readMessage(request);
      if (problem) return error(problem);
      if (!(await allowed(env.REPLY_LIMIT, request))) return error("rate_limited");
      if (!known) return error("unknown_slot");
      return answer(await slot().reply(message));
    }

    if (what === "reply" && method === "GET") {
      if (token === null) return error("forbidden");
      if (!known) return error("unknown_slot");
      return answer(await slot().waitFor("reply", token, waitSeconds(url)));
    }

    if (what === "address" && method === "PUT") {
      const { message, error: problem } = await readMessage(request);
      if (problem) return error(problem);
      if (token === null) return error("forbidden");
      if (!known) return error("unknown_slot");
      return answer(await slot().putAddress(token, message));
    }

    if (what === "address" && method === "GET") {
      if (token === null) return error("forbidden");
      if (!known) return error("unknown_slot");
      return answer(await slot().waitFor("address", token, waitSeconds(url)));
    }

    return error("unknown_slot");
  },
};

/**
 * One slot: the Durable Object of a nameplate.
 *
 * What it stores, under the key "slot":
 *   open:  { open: true, expires, hello, senderToken, receiverToken?, reply?, address? }
 *   ended: { open: false, reason: "used" | "expired" | "closed", until }
 * `expires` and `until` are milliseconds since the epoch. Messages stay base64.
 */
export class Slot extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.settings = settings(env);
    // Requests that wait for a change of this slot
    this.waiting = [];
    this.slot = undefined;
    ctx.blockConcurrencyWhile(async () => {
      this.slot = await ctx.storage.get("slot");
    });
  }

  /** Wake every request that waits */
  changed() {
    const waiting = this.waiting;
    this.waiting = [];
    for (const wake of waiting) wake();
  }

  async save() {
    if (this.slot === undefined) {
      await this.ctx.storage.deleteAll();
      return;
    }
    await this.ctx.storage.put("slot", this.slot);
    // The alarm ends the slot when its time is up, and later forgets how it ended
    await this.ctx.storage.setAlarm(this.slot.open ? this.slot.expires : this.slot.until);
  }

  /** End the slot and remember why */
  async end(reason) {
    this.slot = { open: false, reason, until: Date.now() + this.settings.remember };
    await this.save();
    this.changed();
  }

  /** Expire what is due. Every request does this first. */
  async sweep() {
    const now = Date.now();
    if (this.slot?.open && this.slot.expires <= now) {
      await this.end("expired");
    }
    if (this.slot && !this.slot.open && this.slot.until <= now) {
      this.slot = undefined;
      await this.save();
    }
  }

  async alarm() {
    await this.sweep();
    this.changed();
  }

  /** The error for a slot that is not there */
  missing() {
    return { error: this.slot ? `slot_${this.slot.reason}` : "unknown_slot" };
  }

  /** Who a token belongs to: "sender", "receiver" or null */
  party(token) {
    // Both are compared, whatever the first one says
    const sender = sameToken(this.slot.senderToken, token);
    const receiver = sameToken(this.slot.receiverToken, token);
    return sender ? "sender" : receiver ? "receiver" : null;
  }

  /**
   * Open the slot with the first message, if the nameplate is free. With `freshOnly`
   * also not if it was in use recently. Returns the sender's token, or null.
   */
  async create(hello, freshOnly) {
    await this.sweep();
    if (this.slot?.open) return null;
    if (this.slot && freshOnly) return null;

    const token = newToken();
    this.slot = {
      open: true,
      expires: Date.now() + this.settings.ttl,
      hello,
      senderToken: token,
    };
    await this.save();
    return { token, expiresIn: Math.ceil(this.settings.ttl / 1000) };
  }

  /** The first message. Changes nothing, and can be asked for by anybody, again and again. */
  async look() {
    await this.sweep();
    if (!this.slot?.open) return this.missing();
    // Somebody else already answered, the code is spent
    if (this.slot.reply !== undefined) return { error: "slot_used" };
    return { body: { message: this.slot.hello } };
  }

  /** Store the reply. One reply per slot: this is what limits guessing a code to one attempt. */
  async reply(message) {
    await this.sweep();
    if (!this.slot?.open) return this.missing();
    if (this.slot.reply !== undefined) return { error: "slot_used" };

    const token = newToken();
    this.slot.reply = message;
    this.slot.receiverToken = token;
    this.slot.expires = Math.max(this.slot.expires, Date.now() + this.settings.replyTtl);
    await this.save();
    this.changed();

    return {
      body: {
        token,
        expires_in: Math.ceil((this.slot.expires - Date.now()) / 1000),
      },
    };
  }

  async putAddress(token, message) {
    await this.sweep();
    if (!this.slot?.open) return this.missing();
    if (this.party(token) !== "sender") return { error: "forbidden" };
    // The address answers the reply, and is set once
    if (this.slot.reply === undefined || this.slot.address !== undefined) {
      return { error: "bad_request" };
    }

    this.slot.address = message;
    await this.save();
    this.changed();
    return {};
  }

  /**
   * Wait for the reply (the sender does) or the address (the receiver does), at most
   * `wait` seconds. An empty answer means: nothing yet.
   */
  async waitFor(what, token, wait) {
    const role = what === "reply" ? "sender" : "receiver";
    const deadline = Date.now() + Math.min(wait, this.settings.maxWait) * 1000;

    for (;;) {
      await this.sweep();
      if (!this.slot?.open) return this.missing();
      if (this.party(token) !== role) return { error: "forbidden" };

      const message = this.slot[what];
      if (message !== undefined) {
        // The address is delivered once, then the slot has done its job
        if (what === "address") await this.end("used");
        return { body: { message } };
      }

      const now = Date.now();
      if (now >= deadline) return {};

      // Until something changes, the wait is over, or the slot runs out
      const pause = Math.max(1, Math.min(deadline, this.slot.expires) - now);
      let timer;
      await Promise.race([
        new Promise((wake) => this.waiting.push(wake)),
        new Promise((wake) => (timer = setTimeout(wake, pause))),
      ]);
      clearTimeout(timer);
    }
  }

  /** Give up the slot. Either side may. */
  async close(token) {
    await this.sweep();
    // Already gone is what the caller wanted
    if (!this.slot?.open) return {};
    if (this.party(token) === null) return { error: "forbidden" };

    await this.end("closed");
    return {};
  }
}
