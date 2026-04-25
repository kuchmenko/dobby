//! `dobby keeper ...` — Keeper daemon lifecycle, bootstrap, backup, restore,
//! fingerprint display, key rotation. See issue #1 § CLI commands → Setup.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::not_yet;

/// Port the Keeper's tonic gRPC server binds to — see issue #1
/// § Communication protocol / Keeper LXC first-boot.
const KEEPER_GRPC_PORT: u16 = 8443;

/// Format an IP + the fixed Keeper gRPC port as a `host:port` endpoint.
///
/// `SocketAddr`'s `Display` impl handles the IPv4 vs IPv6 asymmetry —
/// IPv6 is wrapped in `[...]` per RFC 3986 so the trailing `:<port>`
/// doesn't collide with the IP's own colons. A naive
/// `format!("{ip}:{port}")` would produce `fd00::50:8443`, which the
/// shell would accept but the pair parser would read as the address
/// `fd00::0050:8443` with no port.
fn keeper_endpoint(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, KEEPER_GRPC_PORT)
}

/// Family-aware DNS default. Both are Cloudflare's public resolver —
/// same operator behaviour, compatible with the keeper's family so
/// `validate_network_families` doesn't reject the implicit default.
fn default_dns_upstream_for(keeper_ip: IpAddr) -> IpAddr {
    if keeper_ip.is_ipv4() {
        // 1.1.1.1
        IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))
    } else {
        // 2606:4700:4700::1111 — Cloudflare DNS over IPv6.
        IpAddr::V6(
            "2606:4700:4700::1111"
                .parse::<std::net::Ipv6Addr>()
                .unwrap(),
        )
    }
}

/// `dobby keeper <sub>` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeeperCommand {
    /// Generate TLS CA + host cert + bootstrap token; write skeleton
    /// `keeper.toml`. Runs once per Keeper LXC. Interactive prompts
    /// for Proxmox token / GitHub Device Flow / backup passphrase
    /// land in subsequent PRs.
    Init(InitArgs),

    /// Start the Keeper daemon (tonic gRPC server + mDNS + embedded DNS).
    Start(StartArgs),

    /// Print the Keeper's TLS cert SHA-256 fingerprint for out-of-band
    /// pairing over an already-authenticated channel.
    ShowFingerprint,

    /// Rotate the Proxmox API token stored under
    /// `/etc/dobby/secrets/_system/proxmox_token.age`.
    SetProxmoxToken,

    /// Authenticate with GitHub via OAuth Device Flow (dobby3000 App).
    #[command(subcommand)]
    Auth(AuthProvider),

    /// Create a passphrase-encrypted archive of `/etc/dobby/`.
    Backup(BackupArgs),

    /// Restore from a passphrase-encrypted archive.
    Restore(RestoreArgs),

    /// Re-push dobby binary + re-issue mTLS cert to an existing LXC.
    Rebootstrap(RebootstrapArgs),

    /// Rotate the age master key (atomic shadow-directory swap).
    RotateSecretsKey,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Target directory for Keeper state.
    #[arg(long, default_value = "/etc/dobby")]
    pub dir: PathBuf,

    /// Keeper LXC's own IP on `--bridge` (e.g. 10.0.0.50).
    /// Written into `keeper.toml` and embedded as a SAN on the TLS host cert.
    #[arg(long, value_name = "IP")]
    pub keeper_ip: IpAddr,

    /// LAN gateway (e.g. 10.0.0.1).
    #[arg(long, value_name = "IP")]
    pub gateway: IpAddr,

    /// LAN subnet in CIDR form.
    #[arg(long, value_name = "CIDR", default_value = "10.0.0.0/24")]
    pub subnet: String,

    /// Range of IPs allocated to managed LXCs (`<first>-<last>`).
    /// Must be outside the DHCP pool and outside `--keeper-ip`.
    #[arg(long, value_name = "RANGE", default_value = "10.0.0.200-10.0.0.250")]
    pub static_range: String,

    /// Proxmox bridge name.
    #[arg(long, default_value = "vmbr0")]
    pub bridge: String,

    /// Upstream DNS for non-`.dobby` queries. When omitted, defaults
    /// to a DNS resolver in the same address family as `--keeper-ip`
    /// (`1.1.1.1` for IPv4, `2606:4700:4700::1111` for IPv6 —
    /// Cloudflare's public resolver in both cases).
    #[arg(long, value_name = "IP")]
    pub dns_upstream: Option<IpAddr>,

    /// Overwrite an existing non-empty `--dir`.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct StartArgs {
    /// State directory written by `dobby keeper init` (must contain
    /// `keeper.toml` and `tls/host.{crt,key}`).
    #[arg(long, default_value = "/etc/dobby")]
    pub dir: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum AuthProvider {
    /// GitHub OAuth Device Flow (required for Release Watcher).
    Github,
}

#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Read passphrase from this env var.
    #[arg(long, value_name = "VAR", group = "passphrase")]
    pub passphrase_env: Option<String>,
    /// Read plaintext passphrase from this file.
    #[arg(long, value_name = "PATH", group = "passphrase")]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// Read passphrase from stdin.
    #[arg(long, group = "passphrase")]
    pub passphrase_stdin: bool,
    /// Read age-ciphertext passphrase from a systemd credentials file.
    #[arg(long, value_name = "PATH", group = "passphrase")]
    pub passphrase_credentials_file: Option<std::path::PathBuf>,
    /// Raw passphrase (visible in `ps` — only for tests / escape hatch).
    #[arg(long, value_name = "VALUE", group = "passphrase")]
    pub passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Path to the encrypted archive produced by `dobby keeper backup`.
    pub archive: std::path::PathBuf,
    /// Overwrite an existing non-empty `/etc/dobby/` tree.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RebootstrapArgs {
    /// App name of the managed LXC to rebootstrap.
    pub app: String,
}

pub async fn run(cmd: KeeperCommand) -> anyhow::Result<()> {
    match cmd {
        KeeperCommand::Init(args) => run_init(args),
        KeeperCommand::Start(args) => run_start(args).await,
        KeeperCommand::ShowFingerprint => Err(not_yet("Phase 1", "dobby keeper show-fingerprint")),
        KeeperCommand::SetProxmoxToken => Err(not_yet("Phase 1", "dobby keeper set-proxmox-token")),
        KeeperCommand::Auth(AuthProvider::Github) => {
            Err(not_yet("Phase 1", "dobby keeper auth github"))
        }
        KeeperCommand::Backup(_) => Err(not_yet("Phase 2", "dobby keeper backup")),
        KeeperCommand::Restore(_) => Err(not_yet("Phase 2", "dobby keeper restore")),
        KeeperCommand::Rebootstrap(_) => Err(not_yet("Phase 2", "dobby keeper rebootstrap")),
        KeeperCommand::RotateSecretsKey => {
            Err(not_yet("Phase 4", "dobby keeper rotate-secrets-key"))
        }
    }
}

async fn run_start(args: StartArgs) -> anyhow::Result<()> {
    dobby_keeper::run(&args.dir).await?;
    Ok(())
}

fn run_init(args: InitArgs) -> anyhow::Result<()> {
    let dns_upstream = args
        .dns_upstream
        .unwrap_or_else(|| default_dns_upstream_for(args.keeper_ip));

    let req = dobby_core::keeper_init::Request {
        dir: args.dir.clone(),
        keeper_ip: args.keeper_ip,
        gateway: args.gateway,
        dns_upstream,
        subnet: args.subnet,
        static_range: args.static_range,
        bridge: args.bridge,
        force: args.force,
    };

    let outcome = dobby_core::keeper_init::init(&req)?;

    let dir = args.dir.display();
    println!("✓ TLS CA + host cert       → {dir}/tls/{{ca,host}}.{{crt,key}}");
    println!("✓ Bootstrap token          → {dir}/secrets/bootstrap_token");
    println!("✓ keeper.toml skeleton     → {dir}/keeper.toml");
    println!();
    println!(
        "TLS fingerprint (sha256):  {}",
        outcome.tls_fingerprint_sha256
    );
    println!("Bootstrap token:           {}", &*outcome.bootstrap_token);
    println!();
    println!("Pair from your workstation:");
    println!(
        "  dobby pair {} --fingerprint {} --token {}",
        keeper_endpoint(args.keeper_ip),
        outcome.tls_fingerprint_sha256,
        &*outcome.bootstrap_token,
    );
    println!();
    println!("Next, provision the Proxmox API token on the PVE host");
    println!("(the Keeper LXC talks to the Proxmox API via this token, never `pct`):");
    println!("  pveum role add DobbyManager --privs \"VM.Allocate VM.Audit \\");
    println!("      VM.Config.CPU VM.Config.Disk VM.Config.Memory \\");
    println!("      VM.Config.Network VM.Config.Options \\");
    println!("      VM.PowerMgmt Sys.Audit Datastore.AllocateSpace\"");
    println!("  pvesh create /pools --poolid dobby");
    println!("  pveum user add pve-dobby@pve");
    println!("  pveum aclmod /pool/dobby --user pve-dobby@pve --role DobbyManager");
    println!("  pveum user token add pve-dobby@pve dobby --privsep 0");
    println!();
    println!("Copy the resulting secret and run `dobby keeper set-proxmox-token`");
    println!("(next PR). Then: systemctl enable --now dobby-keeper");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn ipv4_endpoint_renders_without_brackets() {
        let ep = keeper_endpoint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)));
        assert_eq!(ep.to_string(), "10.0.0.50:8443");
    }

    #[test]
    fn ipv6_endpoint_renders_with_brackets() {
        let ep = keeper_endpoint(IpAddr::V6("fd00::50".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(ep.to_string(), "[fd00::50]:8443");
    }

    #[test]
    fn ipv6_loopback_endpoint() {
        let ep = keeper_endpoint(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(ep.to_string(), "[::1]:8443");
    }

    #[test]
    fn dns_default_is_v4_for_v4_keeper() {
        let kip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(default_dns_upstream_for(kip).to_string(), "1.1.1.1");
    }

    #[test]
    fn dns_default_is_v6_for_v6_keeper() {
        let kip = IpAddr::V6("fd00::50".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            default_dns_upstream_for(kip).to_string(),
            "2606:4700:4700::1111"
        );
    }
}
