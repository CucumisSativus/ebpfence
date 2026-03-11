mod config;
mod ebpf_provider;
mod event_handler;
mod server;
#[cfg(all(test, feature = "integration"))]
mod integration_tests;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::info;

use config::load_config;
use ebpf_provider::RealEBPFProvider;
use event_handler::{EventHandler, EventHandlerConfig};

#[derive(Parser)]
#[command(name = "ebpfence-daemon", about = "eBPF-based file access monitor")]
struct Args {
    #[arg(short, long, help = "Path to JSON config file")]
    config: PathBuf,

    #[arg(
        short,
        long,
        default_value = "/var/run/ebpfence.sock",
        help = "Path to Unix socket for gRPC API"
    )]
    socket: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    let cfg = load_config(&args.config)?;
    info!(
        patterns = ?cfg.patterns,
        threshold = cfg.threshold,
        strategy = %cfg.strategy,
        "Loaded configuration"
    );

    let provider = Arc::new(RealEBPFProvider::new(&cfg.strategy)?);

    let handler = Arc::new(EventHandler::new(
        provider,
        EventHandlerConfig {
            disallowed_patterns: cfg.patterns,
            threshold: cfg.threshold,
            target_pid: cfg.target_pid,
            strategy: cfg.strategy,
        },
    )?);

    let token = CancellationToken::new();

    // Handle Ctrl-C / SIGTERM
    {
        let t = token.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to listen for Ctrl-C");
            info!("Shutting down...");
            t.cancel();
        });
    }

    // Start gRPC server in background task
    {
        let h = handler.clone();
        let socket = args.socket.clone();
        tokio::spawn(async move {
            if let Err(e) = server::serve(h, &socket).await {
                tracing::error!("gRPC server error: {}", e);
            }
        });
    }

    // Run the event loop (blocks until cancellation)
    handler.clone().run(token).await?;

    println!("\nExiting...");
    Ok(())
}
