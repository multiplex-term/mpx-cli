# mpx — bind a machine to Multiplex

Companion CLI for [Multiplex](https://multiplexterm.dev), the spatial SSH
terminal built around remote tmux. Run one command on a machine and it shows
up on the app's monitor wall — SSH key enrolled, host key fingerprints
pinned, nothing typed.

```
$ mpx bind
● multiplex bind · devbox (192.168.1.24 · ssh :22 · user jhen)
✓ host keys read — ssh-ed25519 SHA256:xK3mVq…
✓ announcing on your network — visible to Multiplex nearby

  [QR code]

  PIN  4 8 2 1 6 3

· clipboard untouched — re-run with --copy to paste this into Multiplex
◌ waiting for Multiplex…
→ Jhen's Vision Pro asks to bind as jhen@devbox — enroll? [Y/n] y
✓ key enrolled → ~/.ssh/authorized_keys (multiplex:bind:9f3a1c2e:jhen-s-vision-pro)
✓ bound. Multiplex has devbox on the wall.
```

Three ways the offer reaches the app, all carrying the same payload:

- **QR** — scan from Multiplex on iPhone or iPad.
- **Local network** — the CLI announces `_multiplex-bind._tcp` (its own
  embedded mDNS announcer, no avahi needed); the machine appears under
  Multiplex's *Add Host ▸ Bind* and the 6-digit PIN confirms it. The
  visionOS path — App Store apps there have no camera QR access. Weaker
  than the other two on a network you don't control: see *Verifying a
  bind*.
- **Clipboard, with `--copy`** — local sessions use the platform clipboard;
  SSH sessions use OSC 52 so the payload lands on your *local* terminal's
  clipboard, and Universal Clipboard carries it to your iPad / iPhone /
  Vision Pro. **Opt-in**: the payload is credential-grade, so `mpx` does
  not take your clipboard — nor, through Universal Clipboard, every
  signed-in device's — unless you ask.

The default handshake **never moves a private key**: the app generates its
own ed25519 keypair and `mpx` appends the public half to
`authorized_keys`, marked in the key's comment field
(`multiplex:bind:<id>:<device>`), so `mpx unbind` can list and remove
exactly what was enrolled.

For machines the device can only reach over SSH itself (a VPS behind a
firewall), `mpx bind --offline` generates a keypair host-side, installs the
public half, and ships the private key inside the payload — the app retires
that key on its first connection and enrolls its own.

## Verifying a bind

The three routes do not carry the same guarantee, and it is worth knowing
which one you are on.

**QR and `--copy` carry this machine's session key.** An app holding that
payload is talking to *this* `mpx bind` process, and nothing else on the
network can answer for it — you read the payload off this terminal, so the
channel is authenticated before any credential moves.

**A PIN typed against a discovered row does not.** That row's session key
arrives over mDNS, which authenticates nothing: any machine on your network
can advertise `_multiplex-bind._tcp` under any name. The PIN proves the app
to *whatever answered*, not that the right machine answered. Prefer the QR on
any network you do not control.

Do **not** treat the fingerprint beside a discovered row as proof of
identity. It rides the same unauthenticated announcement as the rest of that
row, so anything able to impersonate the machine can copy it verbatim.

**The check that works on every route is this terminal.** An enrollment
happens here, or it did not happen to this machine:

1. `mpx bind` prints the `[Y/n]` line, and it names the device you are
   holding.
2. It then prints `✓ bound`.

If Multiplex reports a successful bind while this terminal still sits at
`waiting for Multiplex…`, you did not bind this machine. Press Ctrl-C, delete
the host that appeared in the app, and bind by QR instead.

## Install

```sh
brew install multiplex-term/tap/mpx                        # macOS or Linux
curl -fsSL https://multiplexterm.dev/install-mpx-cli | sh  # macOS or Linux
cargo install --path .                                     # from source
```

The binary is `mpx`; every install channel also provides `multiplex` as an
alias for it.

## Releasing

Tag-driven, from this repository:

```sh
# 1. bump Cargo.toml's version (the workflow refuses a tag that disagrees)
# 2. commit, then:
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` then builds four targets —
`{x86_64,aarch64}-unknown-linux-musl` (static, so one Linux binary covers
glibc distributions and Alpine) and `{x86_64,aarch64}-apple-darwin` —
packages each with the `multiplex` alias, the README and the licence, writes
a `SHA256SUMS`, publishes a GitHub Release into
[`multiplex-cli-releases`](https://github.com/multiplex-term/multiplex-cli-releases),
and opens a formula bump against
[`multiplex-term/homebrew-tap`](https://github.com/multiplex-term/homebrew-tap)
(the repo behind the `multiplex-term/tap` tap — the `homebrew-` prefix is
Homebrew's own resolution rule, not a choice).

Re-running a tag is safe: assets are uploaded with `--clobber`, so one bad
platform build can be fixed without minting a new version.

### Why artifacts live in another repository

Homebrew and `curl | sh` both need *anonymous* downloads, and release
artifacts are large and rewritten every tag. `multiplex-cli-releases`
carries them; it holds no source.

## Protocol

The cross-implementation vectors (`cargo run --example gen_vectors`) are
shared with the Multiplex app's unit tests so the two implementations
cannot drift. The written wire contract is not published yet.

X25519 → HKDF-SHA256 → ChaCha20-Poly1305 over a length-prefixed TCP
exchange; QR/clipboard payloads authenticate with a 16-byte single-use
token (TTL ≤ 10 min, default 1), discovery authenticates with a
transcript-bound PIN proof (3 attempts, then the session locks). Every
enrollment is confirmed on the host's own terminal (`[Y/n]`, or `--yes`) —
which, as *Verifying a bind* explains, is the check that holds when the
discovery route's own guarantee does not.

The payload holds only what is needed to reach and authenticate the machine
— 65 bytes for one IPv4 candidate — so the QR draws in 45 columns beside its
PIN instead of overflowing the terminal. The SSH user and the host key
fingerprints the app pins arrive over the authenticated handshake instead.

`MPX_BIND_TEST_*` environment hooks pin the session's randomness — and
`MPX_BIND_TEST_YES=1` skips the confirmation entirely — for Multiplex's dev
harness. Setting them only weakens a bind the operator deliberately staged,
but one surviving in a shell rc would weaken every later bind silently, so
`mpx bind` names the ones in effect before it prints an offer.
