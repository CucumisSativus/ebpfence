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

    // Start gRPC server. Use &mut so we can await it after select! for clean shutdown.
    let mut server_task = {
        let h = handler.clone();
        let socket = args.socket.clone();
        let t = token.clone();
        tokio::spawn(async move { server::serve(h, &socket, t).await })
    };

    // Race the event loop against the server task.
    // Using &mut server_task so the handle remains accessible after select!.
    tokio::select! {
        result = handler.clone().run(token.clone()) => {
            // Event loop finished (token was cancelled by signal handler).
            // Cancel the token (no-op if already cancelled) and await the server
            // so it can flush in-flight requests before we exit.
            result?;
            token.cancel();
            if let Ok(Err(e)) = server_task.await {
                tracing::warn!("gRPC server error during shutdown: {e}");
            }
        }
        result = &mut server_task => {
            // Server finished while the event loop was still running.
            // Cancel the event loop and report the error — do not await
            // server_task again as it has already resolved.
            token.cancel();
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => anyhow::bail!("gRPC server error: {e}"),
                Err(e) => anyhow::bail!("gRPC server panicked: {e}"),
            }
        }
    }

    println!("\nExiting...");
    Ok(())
}
