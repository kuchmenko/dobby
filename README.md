# dobby

Proxmox LXC deployment automation — a single Rust binary operating in three
modes (CLI, Keeper, Elf) that manages binary artefact deployment across
unprivileged LXC containers.

Full architecture, acceptance criteria, and phased roadmap live in the design
issue: **[kuchmenko/dobby#1](https://github.com/kuchmenko/dobby/issues/1)**.

## Status

Phase 1 (Foundation) — core scaffolding plus the first real Keeper bootstrap path.
`dobby keeper init`, `dobby keeper start`, `dobby keeper show-fingerprint`, and
`dobby pair` are wired; later deployment subcommands still return `unimplemented`.

## Quickstart

```sh
just --list          # see all dev commands
just help            # dobby --help, full CLI surface
just check           # fast compile check across the workspace
just install-dev-tools  # install local Cargo tools used by CI
just ci                 # everything CI runs (fmt + clippy + coverage + buf + audit + deny + msrv + machete + typos + udeps)
```

Keeper bootstrap shape:

```sh
dobby keeper init --keeper-ip 10.0.0.50 --gateway 10.0.0.1
dobby keeper show-fingerprint
dobby pair 10.0.0.50:8443 --fingerprint <sha256> --token <dby_boot_...>
```

## Licence

Dual-licensed under either of

- Apache Licence 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT Licence ([LICENSE-MIT](LICENSE-MIT))

at your option.
