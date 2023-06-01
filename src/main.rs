use async_rwlock::{RwLock, RwLockUpgradableReadGuard};
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use maxminddb::{MaxMindDBError, Mmap, Reader};
use once_cell::sync::OnceCell;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tracing::{debug, error, info, info_span};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

type SharedReader = Arc<RwLock<Reader<Mmap>>>;

#[derive(Parser, Debug)]
struct Config {
    /// The IP and port to listen on
    #[arg(short, long, default_value = "0.0.0.0:3000")]
    listen: SocketAddr,

    /// The location of the GeoLite2 database
    #[arg(short, long, default_value = "GeoLite2-City.mmdb")]
    db: String,

    /// Minimum time before db reloads at /db/reload
    #[arg(long, default_value = "60")]
    db_reload_secs: u64,

    /// Disable DB reloading at runtime
    #[arg(long)]
    disable_db_reloading: bool,
}

enum IpOrigin {
    UserProvided(IpAddr),
    Inferred(IpAddr),
}

impl IpOrigin {
    const fn cache_control(&self) -> &'static str {
        match self {
            Self::UserProvided(_) => "public, max-age=3600, stale-if-error=82800",
            Self::Inferred(_) => "no-store",
        }
    }
}

impl std::ops::Deref for IpOrigin {
    type Target = IpAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::UserProvided(ip) | Self::Inferred(ip) => ip,
        }
    }
}

async fn get_geoip(reader: SharedReader, ip: IpOrigin) -> Result<impl IntoResponse, StatusCode> {
    let reader = reader.read().await;

    let _span = info_span!("get_geoip", ip = %ip.to_string()).entered();

    match reader.lookup::<maxminddb::geoip2::City>(*ip) {
        Ok(city) => {
            debug!("IP in database");
            let mut city_json = serde_json::json!(city);
            if let Some(obj) = city_json.as_object_mut() {
                obj.insert("query".into(), ip.to_string().into());
                obj.insert("error".into(), serde_json::Value::Null);
            }
            // geoip2::City contains values borrowed from reader, so we must render it right away
            Response::builder()
                .header("Content-Type", "application/json")
                .header(http::header::CACHE_CONTROL, ip.cache_control())
                .body(city_json.to_string())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(err) => match err {
            MaxMindDBError::AddressNotFoundError(_) => {
                debug!("IP not in database");
                Err(StatusCode::NO_CONTENT)
            }
            ref e => {
                error!("IP lookup error: {e}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        },
    }
}

async fn get_geoip_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<SharedReader>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    get_geoip(reader, IpOrigin::Inferred(insecure_client_ip)).await
}

async fn get_geoip_with_explicit_ip(
    Extension(reader): Extension<SharedReader>,
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
        resp.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        resp
    }
}

async fn db_reload(
    Extension(reader): Extension<SharedReader>,
    Extension(cfg): Extension<Arc<Config>>,
) -> impl IntoResponse {
    static NEXT_RELOAD_TIME: OnceCell<RwLock<Instant>> = OnceCell::new();

    if cfg.disable_db_reloading {
        debug!("GeoIP DB reload requested, but disabled");
        return ReloadStatus::ReloadingDisabled;
    }

    let now = Instant::now();
    let reload_time = NEXT_RELOAD_TIME.get_or_init(|| RwLock::new(now));

    let reload_time = reload_time.upgradable_read().await;
    if *reload_time <= now {
        let mut reload_time = RwLockUpgradableReadGuard::upgrade(reload_time).await;
        match Reader::open_mmap(&cfg.db) {
            Ok(new_reader) => {
                let mut old_reader = reader.write().await;
                *old_reader = new_reader;
                *reload_time = now + Duration::from_secs(cfg.db_reload_secs);
                debug!("successfully reloaded GeoIP DB");
                ReloadStatus::Success
            }
            Err(err) => {
                error!("error reloading GeoIP, restoring old version: {err}");
                ReloadStatus::InternalServerError(err.to_string())
            }
        }
    } else {
        debug!("GeoIP DB reload requested, but too early to reload");
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

    info!("shutdown request received, shutting down");
}

fn request_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    info_span!(
        "req",
        seq = %SEQ.fetch_add(1, Ordering::Relaxed),
        method = %req.method(),
        path = %req.uri(),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
    let _span = info_span!("main").entered();

    let cfg = Arc::new(Config::parse());
    let reader = Arc::new(RwLock::new(Reader::open_mmap(&cfg.db)?));

    let tcp = TcpListener::bind(cfg.listen)?;
    info!("Listening on {}", cfg.listen);

    let app = axum::Router::new()
        .route("/", get(get_geoip_with_client_ip))
        .route("/:ip", get(get_geoip_with_explicit_ip))
        .route("/db/reload", get(db_reload))
        .layer(Extension(reader))
        .layer(Extension(cfg))
        .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(request_span));

    Ok(axum::Server::from_tcp(tcp)?
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
