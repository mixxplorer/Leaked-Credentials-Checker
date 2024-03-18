use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{routing::post, Router};
use clap::Parser;

mod errors;
mod handlers;

#[derive(Clone)]
struct AppState {
    hash_filter: Arc<lcc_lib::password_filter::PasswordFilter>,
}

impl AppState {
    fn new(filter_file_path: &String) -> Result<AppState> {
        let hash_filter = Arc::new(
            lcc_lib::password_filter::load_filter(filter_file_path)
                .context("Loading filter unsuccessful? Does the filter exist and matches the filter version to the binary version?")?,
        );
        Ok(AppState { hash_filter })
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Exposes a web API, which can be used to check for leaked credentials (passwords)"
)]
pub struct CliArguments {
    #[clap(long, short, default_value = "[::1]:3000", help = "Bind address with port, e.g. [::1]:3000")]
    bind_addr: String,

    #[clap(long, short, default_value = lcc_lib::constants::DEFAULT_FILTER_FILE, help = "Path to read and write the filter to. If re-building filter is requested, this file gets overwritten.")]
    filter_file: String,

    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(args.log_level.log_level().unwrap().to_level_filter())
        .with_utc_timestamps()
        .init()
        .unwrap();

    log::info!("Constructing app state...");
    let state = AppState::new(&args.filter_file)?;
    log::info!("Done constructing app state!");

    // build our application with a single route
    let app = Router::new().route("/v1/hashes/check", post(handlers::check_hash)).with_state(state);

    // run our app with hyper...
    let listener = tokio::net::TcpListener::bind(args.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
