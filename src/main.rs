use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use maxminddb::{MaxMindDBError, Mmap, Reader};
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{Mutex, RwLock};

#[derive(Parser, Debug)]
struct Config {
    /// The IP to listen on
    #[arg(short, long, default_value = "0.0.0.0")]
    ip: IpAddr,

    /// The port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// The location of the GeoLite2 database
    #[arg(short, long, default_value = "GeoLite2-City.mmdb")]
    db: String,

    /// Minimum time before db reloads at /reload_geoip
    #[arg(long, default_value = "60")]
    db_reload_secs: u64,

    /// Disable DB reloading at runtime
    #[arg(long)]
    disable_db_reloading: bool,
}

#[derive(Serialize)]
struct TimezoneErrorResponse {
    error: String,
    query: String,
}

async fn get_geoip(
    reader: Arc<RwLock<Reader<Mmap>>>,
    ip: IpAddr,
) -> (StatusCode, Result<String, Json<TimezoneErrorResponse>>) {
    let reader = reader.read().await;
    match reader.lookup::<maxminddb::geoip2::City>(ip) {
        Ok(city) => {
            // geoip2::City contains values borrowed from reader, so we must render it right away
            let mut city_json = json!(city);
            if let Some(obj) = city_json.as_object_mut() {
                obj.insert("query".into(), ip.to_string().into());
            }
            (StatusCode::OK, Ok(city_json.to_string()))
        }
        Err(err) => {
            let status_code = match err {
                MaxMindDBError::AddressNotFoundError(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status_code,
                Err(Json(TimezoneErrorResponse {
                    query: ip.to_string(),
                    error: err.to_string(),
                })),
            )
        }
    }
}

async fn get_geoip_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    get_geoip(reader, insecure_client_ip).await
}

async fn get_geoip_with_explicit_ip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Path(ip): Path<IpAddr>,
) -> impl IntoResponse {
    get_geoip(reader, ip).await
}

#[derive(Debug)]
enum ReloadStatus {
    Success,
    ReloadingDisabled,
    TooEarlyToReload,
    InternalServerError(String),
}

impl IntoResponse for ReloadStatus {
    fn into_response(self) -> Response {
        let resp = match self {
            Self::Success => (StatusCode::OK, "DB reloaded".to_string()),
            Self::ReloadingDisabled => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "DB reloading disabled at startup".to_string(),
            ),
            Self::TooEarlyToReload => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too early to reload".to_string(),
            ),
            Self::InternalServerError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
        };
        resp.into_response()
    }
}

async fn reload_geoip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Extension(cfg): Extension<Arc<Config>>,
) -> ReloadStatus {
    static NEXT_RELOAD_TIME: OnceCell<Mutex<Instant>> = OnceCell::new();

    if cfg.disable_db_reloading {
        return ReloadStatus::ReloadingDisabled;
    }

    let now = Instant::now();
    let reload_time = NEXT_RELOAD_TIME.get_or_init(|| Mutex::new(now));

    let mut reload_time = reload_time.lock().await;
    if *reload_time <= now {
        match Reader::open_mmap(&cfg.db) {
            Ok(new_reader) => {
                let mut old_reader = reader.write().await;
                *old_reader = new_reader;
                *reload_time = now + Duration::from_secs(cfg.db_reload_secs);
                ReloadStatus::Success
            }
            Err(err) => ReloadStatus::InternalServerError(err.to_string()),
        }
    } else {
        ReloadStatus::TooEarlyToReload
    }
}

async fn wait_for_shutdown_request() {
    let ctrl_c = async { signal::ctrl_c().await.unwrap() };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>(); // unimplemented elsewhere

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Arc::new(Config::parse());
    let reader = Arc::new(RwLock::new(Reader::open_mmap(&cfg.db)?));
    let app = Router::new()
        .route("/", get(get_geoip_with_client_ip))
        .route("/:ip", get(get_geoip_with_explicit_ip))
        .route("/reload/geoip", get(reload_geoip))
        .layer(Extension(reader))
        .layer(Extension(cfg.clone()));
    let addr = SocketAddr::from((cfg.ip, cfg.port));
    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
