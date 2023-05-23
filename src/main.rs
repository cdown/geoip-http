use axum::extract::{Extension, Path};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use maxminddb::{Mmap, Reader};
use once_cell::sync::OnceCell;
use serde::Serialize;
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
) -> Result<Json<TimezoneResponse>, Json<TimezoneErrorResponse>> {
    let reader = reader.read().await;
    match reader.lookup::<maxminddb::geoip2::City>(ip) {
        Ok(city) => Ok(Json(TimezoneResponse {
            tz: city
                .location
                .and_then(|loc| loc.time_zone.map(str::to_string)),
            ip: ip.to_string(),
        })),
        Err(err) => Err(Json(TimezoneErrorResponse {
            ip: ip.to_string(),
            error: err.to_string(),
        })),
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

async fn reload_geoip(
    Extension(reader): Extension<Arc<RwLock<Reader<Mmap>>>>,
    Extension(cfg): Extension<Arc<Config>>,
) -> String {
    static NEXT_RELOAD_TIME: OnceCell<Mutex<Instant>> = OnceCell::new();

    if cfg.disable_db_reloading {
        return "reloading disabled".to_string();
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
                "reloaded".to_string()
            }
            Err(err) => err.to_string(),
        }
    } else {
        "too early to reload".to_string()
    }
}

async fn wait_for_shutdown_request() {
    #[cfg(unix)]
    signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install signal handler")
        .recv()
        .await;
    #[cfg(not(unix))]
    signal::ctrl_c().await.expect("failed to set up ^C handler")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Arc::new(Config::parse());
    let reader = Arc::new(RwLock::new(Reader::open_mmap(&cfg.db)?));
    let app = Router::new()
        .route("/", get(get_tz_with_client_ip))
        .route("/reload_geoip", get(reload_geoip))
        .route("/:ip", get(get_tz_with_explicit_ip))
        .layer(Extension(reader))
        .layer(Extension(cfg.clone()));
    let addr = SocketAddr::from((cfg.ip, cfg.port));
    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
