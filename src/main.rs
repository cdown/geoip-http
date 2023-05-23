use axum::error_handling::HandleErrorLayer;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{BoxError, Json, Router};
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use maxminddb::{MaxMindDBError, Mmap, Reader};
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceBuilder;
use tower_governor::{errors::display_error, governor::GovernorConfigBuilder, GovernorLayer};

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

    /// Enable per-IP ratelimiting
    #[arg(short, long)]
    ratelimit: bool,

    /// Period for per-IP ratelimiting
    #[arg(long, default_value = "60")]
    ratelimit_period_secs: u64,

    /// Maximum number of requests in --ratelimit-period-secs
    #[arg(long, default_value = "5")]
    ratelimit_burst: u32,
}

#[derive(Serialize)]
struct TimezoneResponse {
    tz: Option<String>,
    ip: String,
}

#[derive(Serialize)]
struct TimezoneErrorResponse {
    error: String,
    ip: String,
}

async fn get_tz(
    reader: Arc<RwLock<Reader<Mmap>>>,
    ip: IpAddr,
) -> (
    StatusCode,
    Result<Json<TimezoneResponse>, Json<TimezoneErrorResponse>>,
) {
    let reader = reader.read().await;
    match reader.lookup::<maxminddb::geoip2::City>(ip) {
        Ok(city) => (
            StatusCode::OK,
            Ok(Json(TimezoneResponse {
                tz: city
                    .location
                    .and_then(|loc| loc.time_zone.map(str::to_string)),
                ip: ip.to_string(),
            })),
        ),
        Err(err) => {
            let status_code = match err {
                MaxMindDBError::AddressNotFoundError(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status_code,
                Err(Json(TimezoneErrorResponse {
                    ip: ip.to_string(),
                    error: err.to_string(),
                })),
            )
        }
    }
}

async fn get_tz_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    get_tz(reader, insecure_client_ip).await
}

async fn get_tz_with_explicit_ip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Path(ip): Path<IpAddr>,
) -> impl IntoResponse {
    get_tz(reader, ip).await
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
    let mut app = Router::new()
        .route("/", get(get_tz_with_client_ip))
        .route("/reload_geoip", get(reload_geoip))
        .route("/:ip", get(get_tz_with_explicit_ip))
        .layer(Extension(reader))
        .layer(Extension(cfg.clone()));

    if cfg.ratelimit {
        app = app.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|e: BoxError| async move {
                    display_error(e)
                }))
                .layer(GovernorLayer {
                    config: Box::leak(Box::new(
                        GovernorConfigBuilder::default()
                            .per_second(cfg.ratelimit_period_secs)
                            .burst_size(cfg.ratelimit_burst)
                            .finish()
                            .unwrap(),
                    )),
                }),
        );
    }

    let addr = SocketAddr::from((cfg.ip, cfg.port));
    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
