use clap::Parser;
use qs_rendezvous::{serve, Config};
use std::{net::SocketAddr, process::ExitCode, time::Duration};

/// Rendezvous server for quic-send.
///
/// An untrusted mailbox: it passes a few opaque messages between two peers that share a
/// short code. It has no secrets and stores nothing on disk. Put a reverse proxy with TLS
/// in front of it.
#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    /// Address and port to listen on
    #[clap(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Seconds a code stays valid while nobody has used it
    #[clap(long, default_value_t = 300)]
    ttl: u64,

    /// Take the client address from the last `X-Forwarded-For` entry.
    /// Only set this behind a reverse proxy that sets the header itself.
    #[clap(long)]
    behind_proxy: bool,

    /// Log level
    #[clap(long, short, default_value = "info")]
    log_level: tracing::Level,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(args.log_level)
        .init();

    let config = Config {
        ttl: Duration::from_secs(args.ttl),
        behind_proxy: args.behind_proxy,
        ..Config::default()
    };

    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("error: could not listen on {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };

    tracing::info!("listening on {}", args.listen);

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };

    match serve(listener, config, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
