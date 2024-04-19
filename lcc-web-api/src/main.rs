use std::sync::Arc;

use aide::{
    axum::{
        routing::{get, post_with},
        ApiRouter, IntoApiResponse,
    },
    openapi::{Info, OpenApi},
    redoc::Redoc,
};
use anyhow::{Context, Result};
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

    #[clap(long, short, default_value = lcc_lib::constants::DEFAULT_FILTER_FILE, help = "Path to read filter from.")]
    filter_file: String,

    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

async fn serve_api(axum::Extension(api): axum::Extension<OpenApi>) -> impl IntoApiResponse {
    axum::Json(api)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(args.log_level.log_level().unwrap().to_level_filter())
        .with_utc_timestamps()
        .init()?;

    log::info!("Constructing app state...");
    let state = AppState::new(&args.filter_file)?;
    log::info!("Done constructing app state!");

    // create metadata for API docs
    let mut api = OpenApi {
        info: Info {
            title: "Leaked Credentials Checker API".to_string(),
            description: Some("Check password hashes for their occurrence in known leaks.".to_string()),
            contact: Some(aide::openapi::Contact {
                name: Some("Leonard Marschke".to_string()),
                url: Some("https://rechenknecht.net/mixxplorer/lcc/lcc".to_string()),
                email: Some("leo@mixxplorer.de".to_string()),
                extensions: indexmap::IndexMap::new(),
            }),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    // build our application utilizing the ApiRouter from aide, allowing to automatically add doc
    let app = ApiRouter::new()
        // Add routes of official API
        .api_route("/v1/hashes/check", post_with(handlers::check_hash, handlers::check_hash_desc))
        // Add non-documented routes (e.g. displaying the docs)
        .route("/docs/api.json", get(serve_api))
        .route("/docs", Redoc::new("/docs/api.json").with_title("LCC API").axum_route())
        .route("/", get(|| async { axum::response::Redirect::to("/docs") }))
        // Add global API state
        .with_state(state)
        // Finish building the API
        .finish_api(&mut api)
        // Add aide (open API) extension layer
        .layer(axum::Extension(api))
        .into_make_service();

    // run our app
    let listener = tokio::net::TcpListener::bind(args.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
