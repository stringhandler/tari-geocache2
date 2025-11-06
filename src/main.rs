mod db;
mod handlers;
mod models;
mod routes;
mod scanner;

use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::db::init_database;
use crate::handlers::AppState;
use crate::routes::create_router;
use crate::scanner::start_background_scanner;

#[derive(Parser, Debug, Clone)]
#[command(name = "tarigeocache")]
#[command(about = "Tari Geocache Server", long_about = None)]
struct Args {
    /// Database URL (e.g., sqlite:geocaches.db)
    #[arg(short, long, default_value = "sqlite://data/geocaches.db")]
    database_url: String,

    /// Server port
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Path to wallet executable (e.g., minotari_console_wallet.exe)
    #[arg(short = 'w', long, default_value = "bin/minotari.exe")]
    wallet_exe: String,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tarigeocache=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    tracing::info!("Starting Tari Geocache Server");
    tracing::debug!("Database URL: {}", args.database_url);
    tracing::debug!("Port: {}", args.port);
    tracing::debug!("Wallet executable: {}", args.wallet_exe);

    // Initialize database
    let db = init_database(&args.database_url).await;

    let state = AppState {
        db: db.clone(),
        wallet_exe: args.wallet_exe.clone(),
    };

    // Start background scanner
    start_background_scanner(args.wallet_exe.clone(), db.clone());

    // Build router
    let app = create_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    tracing::info!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
