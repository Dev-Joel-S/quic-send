# quic-send (fork)

A peer-to-peer file transfer tool that uses the QUIC protocol to transfer data over a direct connection.

This is a maintained fork of [maxomatic458/quic-send](https://github.com/maxomatic458/quic-send), which was archived in favor of [fsend](https://github.com/maxomatic458/fsend). The upstream author moved towards WebRTC, this fork stays on QUIC, which is the better fit for large transfers.

> [!NOTE]
> Because quic-send uses NAT traversal, a direct connection might not be possible on every network.

## What this fork changes

- **Short codes instead of long tickets**: upstream prints a base64-encoded iroh `NodeAddr` that is ~60+ characters long. This fork uses an 8-character [Crockford Base32](https://www.crockford.com/base32.html) code that is short enough to read out over the phone.
- **Zero trust by design**: the code is not just a lookup index, it is the shared secret of a [CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) PAKE. The rendezvous server only ever stores an opaque blob and can neither read the peer address nor substitute its own. A hostile rendezvous server can deny service, nothing else.
- **Post-quantum key exchange**: hybrid X25519MLKEM768, so a recorded transfer stays confidential against a future quantum adversary. The PAKE secret and the KEM secret are both mixed into the final key, an attacker has to break both.
- **Optional password**: an extra password can be mixed into the handshake on top of the code. Unlike Magic Wormhole, it is optional, not mandatory.
- **Serverless mode**: no rendezvous at all. Peers exchange address and public key directly, like [transmitic](https://github.com/transmitic/transmitic). Useful for server-to-server transfers and for anyone who does not want to run infrastructure.
- **Self-hosted rendezvous and relay**: no default dependency on infrastructure operated by someone else. Rendezvous URL and iroh relay are configurable, relay can be disabled entirely.
- **CLI only**: the Tauri GUI from upstream has been removed. One binary, no webview, no bundler toolchain.
- **Sane destination handling**: files land in the user's Downloads folder by default instead of the current working directory, existing destination folders are no longer silently merged into, and incomplete transfers are written as `.part` files with a separate resume state.
- **Prebuilt binaries for Linux and Windows**: a static Linux binary that runs on any distribution (Debian, Arch, NixOS, ...), a `.deb` package, an Arch `PKGBUILD` and a standalone Windows `.exe`.

## Features inherited from upstream

- **P2P data transfer**: files are sent over a direct connection, data is never relayed through a server by default.
- **Encryption**: provided by [quinn](https://crates.io/crates/quinn) / [rustls](https://crates.io/crates/rustls), with peer identity pinned through the iroh `NodeId`.
- **Resumable transfers**: if the connection drops, the transfer continues where it left off.
- **Transfer files and folders**
- **No port forwarding required**: UDP hole punching, provided by [iroh](https://github.com/n0-computer/iroh).

## Installation

Prebuilt downloads are on the [releases page](https://github.com/dev-joel-s/quic-send/releases):

| Platform | Download |
|----------|----------|
| Any Linux (Debian, Arch, NixOS, ...) | `qs-<version>-x86_64-linux.tar.gz`, a static binary without dependencies |
| Debian, Ubuntu | `quic-send_<version>-1_amd64.deb`, install with `sudo apt install ./quic-send_*.deb` |
| Windows | `qs-<version>-x86_64-windows.exe`, a standalone executable |

`SHA256SUMS` lists the checksums of all files.

On Arch Linux, build the package with the [PKGBUILD](packaging/arch/PKGBUILD) (`makepkg -si` in that directory). Note that `quickshell` also installs a `qs` command.

From source, with a Rust toolchain:

```bash
cargo install --locked --git https://github.com/dev-joel-s/quic-send qs-cli
```

## Usage

### Sending files

```
$ qs send <file/folder>
code: K7X4M2QP
on the other peer, run the following command:

qs receive K7X4M2QP
```

Paths can be dragged into the terminal window, the shell pastes the quoted path and `qs` handles it.

### Receiving files

```
$ qs receive K7X4M2QP
```

Files go to your Downloads folder. Override with `-o <dir>`, or `-o .` for the current directory.

### With an extra password

```
$ qs send --password <file/folder>
$ qs receive --password K7X4M2QP
```

The password is prompted for, never passed as an argument, and is mixed into the PAKE in addition to the code.

### Without any server

```
$ qs send --direct <file/folder>
$ qs receive --direct <peer-address>
```

The sender prints an address blob including its public key. No rendezvous is contacted. One side needs to be reachable.

### Self-hosted rendezvous

```
$ qs send --rendezvous https://rz.example.com <file/folder>
```

Or set it once in the config file. The rendezvous server is included in this repo.

## Comparison with other file transfer tools

| Feature | quic-send (fork) | upstream quic-send | [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) | [croc](https://github.com/schollz/croc) |
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

\* While it is possible in Magic Wormhole, establishing a direct connection is unlikely, since it tries to establish a direct TCP connection. quic-send uses UDP hole punching instead, which works on most networks.

## Security model

The code is the secret. Anything that sees the code can impersonate either peer, so do not send it through the same channel you expect to be compromised. Everything else is untrusted:

- The rendezvous server sees a slot index derived from part of the code and two opaque PAKE messages. It cannot derive the key, cannot read the peer address, cannot substitute its own.
- The relay, if enabled, sees ciphertext and traffic metadata.
- A wrong code fails the handshake and burns the slot. One guess per attempt, no offline dictionary attack.

## License

MIT, same as upstream.
