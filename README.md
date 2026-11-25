# zeugma (fork)

A peer-to-peer file transfer tool that uses the QUIC protocol to transfer data over a direct connection.

This is a maintained fork of [maxomatic458/quic-send](https://github.com/maxomatic458/quic-send), which was archived in favor of [fsend](https://github.com/maxomatic458/fsend). The upstream author moved towards WebRTC, this fork stays on QUIC, which is the better fit for large transfers.

> [!NOTE]
> zeugma is peer to peer: the two machines talk to each other directly, there is no relay in between. That needs one of them to be reachable by the other: the same network, IPv6 without a blocking firewall, a public IP address or a forwarded UDP port. Behind two NAT routers on IPv4 a connection fails, unless you run [your own relay](#your-own-relay).

## What this fork changes

- **Short codes instead of long tickets**: with a rendezvous server, the sender shows an 8-character [Crockford Base32](https://www.crockford.com/base32.html) code like `K7X4-M2QP`, short enough to read out over the phone. Without one, it prints a ticket as upstream does.
- **Zero trust by design**: the code is not just a lookup index. Its first two characters name a slot on the rendezvous server, the other six are the secret of a [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) PAKE. The server only ever stores opaque blobs and can neither read the peer address nor substitute its own. A hostile rendezvous server can deny service, nothing else.
- **Post-quantum key exchange**: the QUIC handshake uses hybrid X25519MLKEM768 and both sides refuse a connection that fell back to a classical exchange, so a recorded transfer stays confidential against a future quantum adversary. The pairing mixes a PAKE secret and an ML-KEM-768 secret into its keys, an attacker has to break both.
- **Optional password**: an extra password can be required on top of the code or ticket. Unlike Magic Wormhole, it is optional, not mandatory.
- **Serverless mode**: no rendezvous and no relay at all. Peers exchange address and public key directly, like [transmitic](https://github.com/transmitic/transmitic). Useful for server-to-server transfers and for anyone who does not want to run infrastructure.
- **Peer to peer, no third party**: there is no default rendezvous server and no relay. Nothing of the public iroh infrastructure is used, neither its relays nor its address lookup. You can run your own rendezvous server for short codes, and your own relay for networks where a direct connection is impossible.
- **Saved peers**: two machines that saved each other transfer without any code or ticket.
- **CLI only**: the Tauri GUI from upstream has been removed. One binary, no webview, no bundler toolchain.
- **Sane destination handling**: files land in the user's Downloads folder by default instead of the current working directory, existing destination folders are no longer silently merged into, and incomplete transfers are written as `.part` files with a separate resume state.
- **An untrusted peer stays in its box**: file names from the sender cannot leave the destination folder, sizes and counts are limited, and the receiver never writes through a symbolic link.
- **Prebuilt binaries for Linux and Windows**: a static Linux binary that runs on any distribution (Debian, Arch, NixOS, ...), a `.deb` package, an Arch `PKGBUILD` and a standalone Windows `.exe`.

## Features inherited from upstream

- **P2P data transfer**: files are sent over a direct connection between the two machines.
- **Encryption**: QUIC with TLS 1.3, provided by [iroh](https://github.com/n0-computer/iroh) and [rustls](https://crates.io/crates/rustls), with the peer identity pinned through its iroh endpoint id.
- **Resumable transfers**: if the connection drops, the transfer continues where it left off.
- **Transfer files and folders**

## Installation

Prebuilt downloads are on the [releases page](https://github.com/dev-joel-s/quic-send/releases):

| Platform | Download |
|----------|----------|
| Any Linux (Debian, Arch, NixOS, ...) | `zeugma-<version>-x86_64-linux.tar.gz`, static binaries without dependencies: `zeugma` and the rendezvous server `zeugma-rendezvous` |
| Debian, Ubuntu | `zeugma_<version>-1_amd64.deb`, install with `sudo apt install ./zeugma_*.deb` |
| Windows | `zeugma-<version>-x86_64-windows.exe`, a standalone executable |

`<version>` is the version of the release, like `0.5.0` or `0.5.0-beta`. `SHA256SUMS` lists the checksums of all files.

On Arch Linux, download the `PKGBUILD` that is attached to the release and run `makepkg -si` next to it. It builds from the source archive of that release and has its checksum.

On NixOS, or anywhere with Nix, the repo is a flake with `zeugma` and `zeugma-rendezvous` in one package (x86_64-linux):

```
nix run github:dev-joel-s/quic-send -- send <file/folder>
nix profile install github:dev-joel-s/quic-send
```

In a NixOS configuration, add `inputs.zeugma.url = "github:dev-joel-s/quic-send";` and put `inputs.zeugma.packages.${pkgs.system}.default` into `environment.systemPackages`. `nix develop` gives a shell with the Rust toolchain for working on the code. The package links the `aws-lc` of nixpkgs instead of the copy inside the Rust crate, and its build runs the tests with it.

From source, with a Rust toolchain:

```bash
cargo install --locked --git https://github.com/dev-joel-s/quic-send qs-cli
```

## Usage

### Sending and receiving

Without a rendezvous server, the sender prints a ticket that carries its address and public key:

```
$ zeugma send <file/folder>
Ticket:

qs1:TYXpn-lm8ladLNDYvhrI_nKROlu2vy2HvxDI6Ync2pIBAQDAAAICme8C

on the other peer, run the following command:

zeugma receive <ticket>
```

With a rendezvous server (see [below](#running-a-rendezvous-server)), it shows a short code instead:

```
$ zeugma send --rendezvous https://rz.example.com <file/folder>
Code:

K7X4-M2QP

on the other peer, run the following command:

zeugma receive K7X4-M2QP
```

The receiver needs the same rendezvous server. Several can be listed (`rendezvous = [...]` in the config file, or `--rendezvous` more than once): the sender uses the first one that answers, the receiver looks for the code on them in the same order. Keep the list the same on both sides: if the two end up on different servers, the receiver can meet somebody else's code that happens to have the same first two characters there, and both pairings fail. The code can be typed with or without the dash and in any case, `I`, `L` and `O` are read as `1` and `0`. A code works once: after a wrong attempt the sender starts again and gets a new one.

The code or ticket is not copied to the clipboard unless you add `--copy` (or set `clipboard = true` in the config file).

Both sides print a short fingerprint of their own id and of the peer's (`This device`, `Sender`, `Receiver`). Compare them if you want to be sure who is on the other end.

### Dragging files into the terminal

Paths can be dragged into the terminal window, the shell pastes the quoted path and `zeugma` handles it.

Or run `zeugma send` without any path and drag files and folders into the window one after another. Each one is listed with its size, an empty line starts the transfer:

```
$ zeugma send
Drag files or folders into this window, or type their paths.
Press Enter on an empty line to send them, Ctrl+C to cancel.

> '/home/joel/Pictures/Holiday 2026'
  + Holiday 2026/ 1.21 GiB
> /home/joel/doc.pdf
  + doc.pdf 340.12 KiB
>
```

The different ways terminals paste a dropped path are understood: single quotes, backslash escapes, `file://` URIs, bare paths with spaces and, on Windows, double quotes.

### Where the files go

Files go to your Downloads folder, the path is printed before anything is received. Override with `-o <dir>`. `--here` (or `-o .`) saves into the directory you are in.

- A file or folder whose name is already taken is saved as `name (1)`, `name (2)`, ... Nothing is merged into or overwritten, unless you pass `-f`.
- Incoming files are written as `<name>.part` and renamed when complete, so an interrupted folder already holds every finished file under its real name.
- An interrupted transfer is resumed when the same thing is sent again. A hidden `.<name>.qs-resume.json` next to the destination tells an interrupted transfer apart from an unrelated folder with the same name. If the source changed in between, it is received as a new copy.

### With an extra password

```
$ zeugma send --password <file/folder>
$ zeugma receive K7X4-M2QP
```

The password is prompted for, never passed as an argument or read from a pipe. The receiver is asked for it on its own when the sender set one, `zeugma receive --password` asks right away.

With a short code the password goes into the PAKE in addition to the code. With a ticket it is checked inside the connection, again with a PAKE, so it is never sent. The sender allows three wrong attempts.

### Without any server

```
$ zeugma send --port 4433 <file/folder>
Ticket:

qs1:TYXpn-lm8ladLNDYvhrI_nKROlu2vy2HvxDI6Ync2pIBAQDAAAICme8C

or, typed by hand, one of:

192.168.1.5:4433/4d85e99fe966f2569d2cd0d8be1ac8fe72913a5bb6bf2d87bf10c8e989dcda92

$ zeugma receive 192.168.1.5:4433/4d85e99f...
```

Nothing but the two machines is involved. The address always comes with the public key: an IP address alone could not be authenticated and is refused.

The sender has to be reachable by the receiver: the same network, IPv6 without a firewall that blocks it, a public IP address, or a forwarded UDP port. `--port` gives the sender a fixed port to forward. There is no hole punching, which needs a relay to coordinate.

`zeugma send --direct` prints a ticket even when a rendezvous server is configured.

### Saved peers

Two machines that transfer often can save each other once and need no code afterwards:

```
laptop$  zeugma send --save-peer homelab <file>
homelab$ zeugma receive --save-peer laptop <code or ticket>
```

From then on:

```
homelab$ zeugma receive --from laptop
laptop$  zeugma send --to homelab <file/folder>
```

`zeugma peers` lists the saved peers, `zeugma peers remove <name>` forgets one.

A saved peer is recognized by its public key, no server takes part in that. For this, both machines use a key that stays the same, kept in `identity.key` in the config directory. Every other transfer uses a fresh key, so nothing links one transfer to the next. A key that stays can be recognized by the relay, which is the price of not needing a code.

Only your user can read `identity.key`: mode 0600 on Linux, and on Windows an access list of its own with your account as the only entry, nothing inherited from the folder. That does not stop an administrator, a backup or somebody who reads the disk from another system. `zeugma peers passphrase` seals the key with a passphrase as well (PBKDF2-HMAC-SHA256 with 600,000 rounds and ChaCha20-Poly1305, both from aws-lc-rs). You are then asked for it whenever a saved peer is used. An empty passphrase removes it again, and a forgotten one cannot be recovered: remove the file and save your peers again. Run `zeugma peers passphrase` before the first `--save-peer` if you want a key that was never on the disk without the passphrase. Sealing a key that was already stored cannot undo that, the old copy may still be found by somebody who reads the disk itself.

The peer is dialed at the address it had when it was saved (its IP addresses, and its relay if you run one). If it moved, pair once more with `--save-peer`. Give the receiving machine a fixed `--port`, so the address stays the same.

If a peer is saved after a transfer with a plain ticket and no password, the sender asks first and shows the receiver's fingerprint to compare, because anyone who had the ticket could be that receiver.

### Config file

`zeugma config` shows where the config file is and which settings are in effect. Flags on the command line override it.

```toml
# ~/.config/zeugma/config.toml on Linux, %APPDATA%\zeugma\config.toml on Windows

# Rendezvous servers for short codes, tried in this order. Without one, zeugma prints
# a ticket instead. No server is built into the program.
rendezvous = ["https://rz.example.com", "https://backup.example.org"]
# "disabled" (no relay, the default) or the URL of your own relay
relay = "disabled"
# Where received files go. "." is the directory zeugma is started in.
output_dir = "/home/me/Downloads"
# Fixed UDP port instead of a random one
port = 4433
# Copy codes and tickets to the clipboard, off by default
clipboard = false

# Peers by id, in addition to the ones saved with --save-peer
[known_peers]
homelab = "4d85e99fe966f2569d2cd0d8be1ac8fe72913a5bb6bf2d87bf10c8e989dcda92"
```

A mistake in the file, including a setting that does not exist, is an error with the line it is on.

The program was called quic-send before. If the `quic-send` folder of an older version is there and the `zeugma` one is not, it is moved on the first start, with the settings, the saved peers and the identity.

## Running a rendezvous server

No rendezvous server is built into `zeugma`. Short codes need one that you or somebody you know runs, and its address in the config file of both sides. There are two implementations of the same API ([docs/rendezvous-api.md](docs/rendezvous-api.md)), a client cannot tell them apart:

- A **Cloudflare Worker**, in [rendezvous-worker](rendezvous-worker/). This is the one to start with: no machine to look after, and no domain of your own needed, Cloudflare gives it a `workers.dev` address. Every code has its own Durable Object. With a free Cloudflare account and Node.js:

  ```
  cd rendezvous-worker
  npm ci
  npx wrangler login
  npx wrangler deploy
  ```

  `deploy` prints the address, which goes into `rendezvous = [...]` in the config file of both sides. More in [rendezvous-worker/README.md](rendezvous-worker/README.md).
- The **Rust server** `zeugma-rendezvous`, in this repo and in the Linux download, for your own machine.

Both pass three opaque messages between the two peers of a pairing and have no secrets. The rest of this section is about the Rust server, which keeps everything in memory.

```
$ zeugma-rendezvous --listen 127.0.0.1:8080
```

Put a reverse proxy with TLS in front of it and tell the server to take the client address from the proxy, so the limits per address work. With [Caddy](https://caddyserver.com):

```
rz.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```
$ zeugma-rendezvous --listen 127.0.0.1:8080 --behind-proxy
```

Only use `--behind-proxy` behind a proxy that sets `X-Forwarded-For` itself, otherwise clients can pick their own address. With nginx that is `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`. An example systemd unit is in [packaging/zeugma-rendezvous.service](packaging/zeugma-rendezvous.service).

Plain `http://` works too, for a server on your own network. The messages stay sealed, but the pairing can be watched and disturbed on the way, and `zeugma` says so.

A code is valid for five minutes (`--ttl`) and good for one attempt. That one attempt is what makes a six character secret enough. Looking at a slot is not an attempt: anyone can fetch the first message of any of the 1024 slots as often as they like, it gives nothing away and changes nothing. What uses up a code is a reply to its slot, right or wrong. So somebody who can reach the server can still make a pairing fail by sending a wrong reply before the real receiver does. They learn nothing, and the server limits replies per address, but on a server that is open to the internet expect that this can happen.

What a server has to do is written down in [docs/rendezvous-api.md](docs/rendezvous-api.md), with a version in the protocol, so another implementation can take its place.

### Your own relay

By default there is no relay: the two machines connect directly or not at all. If both sit behind NAT routers on IPv4, that fails. For that case you can run your own relay, iroh's relay server (see the [iroh documentation](https://github.com/n0-computer/iroh)), and point both sides at it with `relay = "https://relay.example.com"`. It helps the two find a direct path (hole punching), and carries the encrypted traffic if there is none. It only ever sees ciphertext. The public relays of the iroh project are not used, `relay = "default"` is refused with a message.

## Comparison with other file transfer tools

| Feature | zeugma (fork) | upstream quic-send | [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) | [croc](https://github.com/schollz/croc) |
|---------|------------------|--------------------|--------------------------------------------------------------------|-----------------------------------------|
| Encryption | ✅ | ✅ | ✅ | ✅ |
| Direct (P2P) transfer | ✅ | ✅ | (✅)* | ❌ |
| Resumable transfers | ✅ | ✅ | ❌ | ✅ |
| Transfer files & folders | ✅ | ✅ | ✅ | ✅ |
| Short human-readable code | ✅ | ❌ | ✅ | ✅ |
| PAKE (server cannot MitM) | ✅ | ❌ | ✅ | ✅ |
| Post-quantum key exchange | ✅ | ❌ | ❌ | ❌ |
| Works without any server | ✅ | ❌ | ❌ | ❌ |
| Self-hostable infrastructure | ✅ | (✅) | ✅ | ✅ |

\* While it is possible in Magic Wormhole, establishing a direct connection is unlikely, since it tries to establish a direct TCP connection. zeugma connects directly over UDP, and with your own relay also through NAT by hole punching.

## Security model

The code, or the ticket, is the secret. Anyone who sees it in time can take the place of the receiver, so do not send it through a channel you expect to be compromised. A password on top closes that gap. Everything else is untrusted:

- **The rendezvous server** sees the first two characters of the code, three opaque messages and the IP addresses of the two peers. It cannot derive the keys, cannot read the peer address, cannot substitute its own. A replaced key or a changed message gives the two sides different keys and the pairing fails.
- **The relay**, if enabled, sees ciphertext and who talks to whom.
- **The other peer** is authenticated, not trusted. It cannot write outside the destination folder and cannot make the receiver run out of memory with oversized or deeply nested offers.
- **A wrong code** fails on both sides and uses the code up. One guess per code, with a chance of one in a billion, and no offline dictionary attack.
- **With a ticket and no password**, the first peer to connect is the receiver. That is all a ticket can promise.

### Post-quantum protection

What a quantum computer could do to zeugma, and what is done about it:

| Part | Algorithm | Against a recorded transfer that is attacked later | Against an attacker who has a quantum computer while the transfer runs |
|------|-----------|-----------------------------------------------------|------------------------------------------------------------------------|
| File data (QUIC connection) | hybrid X25519 + ML-KEM-768 (`X25519MLKEM768`), both sides refuse anything else | protected, an attacker has to break both | the key exchange is protected, see the next row for the identity |
| Who is on the other end | Ed25519 keys (the iroh endpoint ids), classical | not affected, a signature is only useful live | **not protected**: such an attacker could pose as the peer. This needs a quantum computer at the time of the transfer and the ticket or the saved peer's key |
| Pairing with a short code, the sealed peer address | CPace (classical) plus ML-KEM-768, both go into the key | protected, the address stays sealed even if CPace falls later | see the next row |
| Telling a right code from a wrong one | CPace on ristretto255, classical | not affected, the code is used up after one attempt | **not protected**: with a quantum computer an attacker could test guesses at a code while it is valid (five minutes). Unlike SPAKE2, CPace has no fixed constants whose one-time break opens every code, each single guess costs a discrete logarithm of its own |
| Password on top of the code | the same CPace | as above | as above |

In short: what you send stays confidential against a quantum computer that appears later. Authentication, who is on the other end, is classical, as it is in every post-quantum hybrid that exists in TLS today. No audited post-quantum PAKE exists, so none is used. The ML-KEM-768 is the formally verified one from [libcrux](https://github.com/cryspen/libcrux) for the pairing, and the one of [aws-lc](https://github.com/aws/aws-lc-rs) inside the QUIC handshake.

What you should know before relying on it:

- The PAKE is CPace on ristretto255 from the [`pake-cpace`](https://crates.io/crates/pake-cpace) crate, which has not had an independent audit and is an early variant of CPace, not byte for byte the CFRG draft. The ML-KEM-768 of a pairing is the formally verified one from [libcrux](https://github.com/cryspen/libcrux) (`libcrux-ml-kem`). Everything else cryptographic comes from [aws-lc-rs](https://github.com/aws/aws-lc-rs) and rustls, including the hybrid key exchange of the QUIC connection.
- Codes and tickets are not copied to the clipboard unless you ask for it, with `--copy` or `clipboard = true` in the config file. A clipboard history or a synced clipboard (Windows can sync it to the cloud) would show them to others before they are used.
- The code of this fork has not been audited by anyone outside either.
- CI checks every dependency with [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) on every change and once a week: known vulnerabilities, licenses, and that every crate comes from crates.io (`deny.toml`). `cargo deny check` runs the same locally.

## License

MIT, same as upstream.
