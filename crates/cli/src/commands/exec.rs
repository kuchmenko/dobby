//! `dobby exec` — run a command inside an LXC, a service user, or an
//! OCI container. Routing is determined by `--service` + service type.
//! See issue #1 § `dobby exec` — use cases and routing.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// App name.
    pub name: String,

    /// Target a specific service (required to enter a container).
    #[arg(long, value_name = "SVC")]
    pub service: Option<String>,

    /// Command + args to execute.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub async fn run(_args: ExecArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 4", "dobby exec"))
}
