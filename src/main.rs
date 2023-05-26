use axum::body::Body;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use http::{HeaderValue, Request};
use maxminddb::{MaxMindDBError, Mmap, Reader};
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{Mutex, RwLock};
use tower_http::trace::{self, TraceLayer};
use tracing::{error_span, Level};

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

enum IpOrigin {
    UserProvided(IpAddr),
    Inferred(IpAddr),
}

impl IpOrigin {
    fn cache_control(&self) -> &'static str {
        match self {
            IpOrigin::UserProvided(_) => "public, max-age=3600, stale-if-error=82800",
            IpOrigin::Inferred(_) => "no-store",
        }
    }
}

impl std::ops::Deref for IpOrigin {
    type Target = IpAddr;

    fn deref(&self) -> &IpAddr {
        match self {
            IpOrigin::UserProvided(ip) | IpOrigin::Inferred(ip) => ip,
        }
    }
}

async fn get_geoip(
    reader: Arc<RwLock<Reader<Mmap>>>,
    ip: IpOrigin,
) -> Result<impl IntoResponse, StatusCode> {
    let reader = reader.read().await;

    match reader.lookup::<maxminddb::geoip2::City>(*ip) {
        Ok(city) => {
            let mut city_json = json!(city);
            if let Some(obj) = city_json.as_object_mut() {
                obj.insert("query".into(), ip.to_string().into());
                obj.insert("error".into(), serde_json::Value::Null);
            }
            // geoip2::City contains values borrowed from reader, so we must render it right away
            Response::builder()
                .header("Content-Type", "application/json")
                .header("Cache-Control", ip.cache_control())
                .body(city_json.to_string())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(err) => {
            let status_code = match err {
                MaxMindDBError::AddressNotFoundError(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Response::builder()
                .status(status_code)
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-store")
                .body(
                    json!(TimezoneErrorResponse {
                        query: ip.to_string(),
                        error: err.to_string(),
                    })
                    .to_string(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_geoip_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    get_geoip(reader, IpOrigin::Inferred(insecure_client_ip)).await
}

async fn get_geoip_with_explicit_ip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Path(ip): Path<IpAddr>,
) -> impl IntoResponse {
    get_geoip(reader, IpOrigin::UserProvided(ip)).await
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
        let mut resp = resp.into_response();
        resp.headers_mut()
            .insert("Cache-Control", HeaderValue::from_static("no-store"));
        resp
    }
}

async fn reload_geoip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Extension(cfg): Extension<Arc<Config>>,
) -> impl IntoResponse {
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

#[tracing_attributes::instrument]
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

    tracing::info!("Request received, shutting down");
}

fn request_span(req: &Request<Body>) -> tracing::Span {
    static SEQ: AtomicUsize = AtomicUsize::new(0);

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    error_span!(
        "req",
        seq,
        method = %req.method(),
        uri = %req.uri(),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(false).init();
    let _span = tracing::info_span!("main").entered();

    let cfg = Arc::new(Config::parse());
    let reader = Arc::new(RwLock::new(Reader::open_mmap(&cfg.db)?));

    let app = Router::new()
        .route("/", get(get_geoip_with_client_ip))
        .route("/:ip", get(get_geoip_with_explicit_ip))
        .route("/reload/geoip", get(reload_geoip))
        .layer(Extension(reader))
        .layer(Extension(cfg.clone()))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(request_span)
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO))
                .on_request(trace::DefaultOnRequest::new().level(Level::INFO)),
        );

    let addr = SocketAddr::from((cfg.ip, cfg.port));
    tracing::info!("Preparing to listen on {}", addr);

    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
