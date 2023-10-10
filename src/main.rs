use async_rwlock::{RwLock, RwLockUpgradableReadGuard};
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use ip2location::DB;
use ip2location::Record;
use maxminddb::{MaxMindDBError, Mmap, Reader};
use once_cell::sync::OnceCell;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::signal;
use tracing::{debug, error, info, info_span};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

type SharedReader = Arc<RwLock<Reader<Mmap>>>;
type SharedReaderIp2location = Arc<Mutex<ip2location::DB>>;

#[derive(Parser, Debug)]
struct Config {
    /// The IP and port to listen on
    #[arg(short, long, default_value = "[::]:3000")]
    listen: SocketAddr,

    /// The location of the GeoLite2 or IP2Location LITE database
    #[arg(short, long)]
    db: PathBuf,

    /// Minimum time before db reloads at /db/reload
    #[arg(long, default_value = "60")]
    db_reload_secs: u64,

    /// Disable DB reloading at runtime
    #[arg(long)]
    disable_db_reloading: bool,

    /// Use IP2Location or Maxmind database
    #[arg(short, long)]
    mode: String,
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

async fn lookup(reader: SharedReaderIp2location, ip: IpOrigin) -> Result<impl IntoResponse, StatusCode> {
    let record2 = &reader.lock().await.ip_lookup(ip.to_string().parse().unwrap());

    let _span = info_span!("lookup", ip = %ip.to_string()).entered();

    match record2 {
        Ok(record) => {
            debug!("IP in database");
            let record1 = if let Record::LocationDb(rec) = record {
                Some(rec)
            } else {
                None
            };
            let record3 = record1.unwrap();
            let city_json = record3.to_json();
            Response::builder()
                .header("Content-Type", "application/json")
                .header(http::header::CACHE_CONTROL, ip.cache_control())
                .body(city_json)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(err) => match err {
            ip2location::error::Error::IoError(_) => {
                error!("{:?}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            ip2location::error::Error::GenericError(_) => {
                error!("{:?}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            ip2location::error::Error::RecordNotFound => {
                error!("{:?}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            ip2location::error::Error::UnknownDb => {
                error!("{:?}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            ip2location::error::Error::InvalidBinDatabase(_, _) => {
                error!("{:?}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        },
    }
}

#[axum_macros::debug_handler]
async fn get_geolocation_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<SharedReaderIp2location>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    lookup(reader, IpOrigin::Inferred(insecure_client_ip)).await
}

async fn get_geolocation_with_explicit_ip(
    Extension(reader): Extension<SharedReaderIp2location>,
    Path(ip): Path<IpAddr>,
) -> impl IntoResponse {
    lookup(reader, IpOrigin::UserProvided(ip)).await
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
    Success { old_ver: u64, new_ver: u64 },
    ReloadingDisabled,
    TooEarlyToReload,
    InternalServerError(String),
}

impl IntoResponse for ReloadStatus {
    fn into_response(self) -> Response {
        let resp = match self {
            Self::Success { old_ver, new_ver } => (
                StatusCode::OK,
                format!("DB reloaded, old version {old_ver}, new version {new_ver}"),
            ),
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
        match Reader::open_mmap(&cfg.db) {
            Ok(new_reader) => {
                let mut reload_time = RwLockUpgradableReadGuard::upgrade(reload_time).await;
                let old_reader = reader.upgradable_read().await;

                let old_dt = &old_reader.metadata.database_type;
                let new_dt = &new_reader.metadata.database_type;
                if new_dt != old_dt {
                    let msg = format!("Refusing to change database type from {old_dt} to {new_dt}");
                    error!("{}", msg);
                    return ReloadStatus::InternalServerError(msg);
                }

                let mut old_reader = RwLockUpgradableReadGuard::upgrade(old_reader).await;

                let old_ver = old_reader.metadata.build_epoch;
                let new_ver = new_reader.metadata.build_epoch;

                *old_reader = new_reader;
                *reload_time = now + Duration::from_secs(cfg.db_reload_secs);
                debug!("successfully reloaded GeoIP DB");
                ReloadStatus::Success { new_ver, old_ver }
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

async fn db_epoch(Extension(reader): Extension<SharedReader>) -> impl IntoResponse {
    let reader = reader.read().await;
    let mut resp = reader.metadata.build_epoch.to_string().into_response();
    resp.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    resp
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
async fn main() -> Result<(), anyhow::Error> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .init();
    let _span = info_span!("main").entered();

    let cfg = Arc::new(Config::parse());
    let _ = if &cfg.mode == "ip2location" {
        let db_mmap = DB::from_file_mmap(&cfg.db)?;
        let reader = Arc::new(Mutex::new(db_mmap));

        let tcp = TcpListener::bind(cfg.listen)?;
        info!("Listening on {}", cfg.listen);
        
        let app = axum::Router::new()
            .route("/", get(get_geolocation_with_client_ip))
            .route("/:ip", get(get_geolocation_with_explicit_ip))
            // .route("/db/reload", get(db_reload))
            // .route("/db/epoch", get(db_epoch))
            .layer(Extension(reader))
            .layer(Extension(cfg))
            .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(request_span));

        Ok::<(), ip2location::error::Error>(axum::Server::from_tcp(tcp)?
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(wait_for_shutdown_request())
            .await?)
    } else if &cfg.mode == "maxmind" {
        let reader = Reader::open_mmap(&cfg.db)?;
        if reader.metadata.database_type != "GeoLite2-City" {
            anyhow::bail!("Invalid database type: {}", reader.metadata.database_type);
        }
        let reader = Arc::new(RwLock::new(reader));
        
        let tcp = TcpListener::bind(cfg.listen)?;
        info!("Listening on {}", cfg.listen);
        
        let app = axum::Router::new()
        .route("/", get(get_geoip_with_client_ip))
        .route("/:ip", get(get_geoip_with_explicit_ip))
        .route("/db/reload", get(db_reload))
        .route("/db/epoch", get(db_epoch))
        .layer(Extension(reader))
        .layer(Extension(cfg))
        .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(request_span));
        
        Ok(axum::Server::from_tcp(tcp)?
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
    } else {
		anyhow::bail!("Invalid mode value, only ip2location or maxmind is accepted.");
	};
    
    Ok(())
}
