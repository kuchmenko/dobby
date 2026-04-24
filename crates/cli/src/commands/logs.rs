//! `dobby logs` — stream app / host / audit logs. See issue #1 §
//! Logging & audit (three log streams).

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct LogsArgs {
    /// App name (omit with `--host` or `--audit`).
    pub name: Option<String>,

    /// Target a specific service's logs.
    #[arg(long, value_name = "SVC")]
    pub service: Option<String>,

    /// Follow the log stream.
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Number of lines to show before following.
    #[arg(long, short = 'n', value_name = "N")]
    pub lines: Option<u32>,

    /// ISO-8601 timestamp lower bound.
    #[arg(long, value_name = "T")]
    pub since: Option<String>,

    /// Log level filter (trace|debug|info|warn|error).
    #[arg(long, short = 'L', value_name = "LEVEL")]
    pub level: Option<String>,

    /// Stream Keeper logs (journald on the Keeper LXC).
    #[arg(long, group = "target")]
    pub host: bool,

    /// Stream the audit log (JSONL on the Keeper LXC).
    #[arg(long, group = "target")]
    pub audit: bool,

    /// Filter audit events to a specific app (only with `--audit`).
    #[arg(long, value_name = "NAME", requires = "audit")]
    pub app: Option<String>,

    /// Filter audit events to a specific event type (only with `--audit`).
    #[arg(long, value_name = "EVENT", requires = "audit")]
    pub r#type: Option<String>,
}

pub async fn run(_args: LogsArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 4", "dobby logs"))
}
