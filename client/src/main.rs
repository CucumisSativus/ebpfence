use clap::{Parser, Subcommand};
use tonic::transport::Channel;

mod proto {
    tonic::include_proto!("ebpfence");
}

use proto::ebp_fence_client::EbpFenceClient;
use proto::{ListBlockedPiDsRequest, UnblockPidRequest};

#[derive(Parser)]
#[command(name = "ebpfence-client", about = "eBPFence daemon client")]
struct Args {
    #[arg(
        short,
        long,
        default_value = "/var/run/ebpfence.sock",
        help = "Path to daemon Unix socket"
    )]
    socket: String,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List all currently blocked PIDs
    List,
    /// Unblock a specific PID
    Unblock {
        /// PID to unblock
        pid: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut client = connect(&args.socket).await?;

    match args.command.unwrap_or(Cmd::List) {
        Cmd::List => list_blocked_pids(&mut client).await?,
        Cmd::Unblock { pid } => unblock_pid(&mut client, pid).await?,
    }

    Ok(())
}

async fn connect(socket_path: &str) -> anyhow::Result<EbpFenceClient<Channel>> {
    let path = socket_path.to_string();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:0")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                // Wrap in hyper_util::rt::TokioIo to implement hyper's IO traits.
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| anyhow::anyhow!("could not reach daemon at {}: {}", socket_path, e))?;

    Ok(EbpFenceClient::new(channel))
}

async fn list_blocked_pids(client: &mut EbpFenceClient<Channel>) -> anyhow::Result<()> {
    let resp = client
        .list_blocked_pi_ds(ListBlockedPiDsRequest {})
        .await?
        .into_inner();

    if resp.blocked_pids.is_empty() {
        println!("No blocked PIDs.");
        return Ok(());
    }

    println!("{:<10} {}", "PID", "VIOLATIONS");
    for bp in resp.blocked_pids {
        println!("{:<10} {}", bp.pid, bp.violation_count);
    }
    Ok(())
}

async fn unblock_pid(client: &mut EbpFenceClient<Channel>, pid: u32) -> anyhow::Result<()> {
    if pid == 0 {
        anyhow::bail!("invalid PID: 0");
    }
    client
        .unblock_pid(UnblockPidRequest { pid })
        .await
        .map_err(|e| anyhow::anyhow!("could not unblock PID {}: {}", pid, e))?;
    println!("PID {} has been unblocked.", pid);
    Ok(())
}
