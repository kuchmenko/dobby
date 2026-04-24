# dobby

Proxmox LXC deployment automation — a single Rust binary operating in three
modes (CLI, Keeper, Elf) that manages binary artefact deployment across
unprivileged LXC containers.

Full architecture, acceptance criteria, and phased roadmap live in the design
issue: **[kuchmenko/dobby#1](https://github.com/kuchmenko/dobby/issues/1)**.

## Status

Phase 1 (Foundation) — scaffolding. Nothing is wired yet; every subcommand
returns `unimplemented` until its phase lands.

## Quickstart

```sh
just --list          # see all dev commands
just help            # dobby --help, full CLI surface
just check           # fast compile check across the workspace
just ci              # everything CI runs (fmt + clippy + check + test + buf)
```

## Licence

Dual-licensed under either of

- Apache Licence 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT Licence ([LICENSE-MIT](LICENSE-MIT))

at your option.
