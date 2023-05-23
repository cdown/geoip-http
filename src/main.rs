use axum::extract::{Extension, Path};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use axum_client_ip::InsecureClientIp;
use clap::Parser;
use maxminddb::Reader;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::signal;

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

fn get_tz(
    reader: Arc<Reader<Vec<u8>>>,
    ip: IpAddr,
) -> Result<Json<TimezoneResponse>, Json<TimezoneErrorResponse>> {
    let city: Result<maxminddb::geoip2::City, _> = reader.lookup(ip);
    let city = match city {
        Ok(city) => city,
        Err(err) => {
            return Err(Json(TimezoneErrorResponse {
                ip: ip.to_string(),
                error: err.to_string(),
            }))
        }
    };
    Ok(Json(TimezoneResponse {
        tz: city
            .location
            .as_ref()
            .and_then(|loc| loc.time_zone.map(str::to_string)),
        ip: ip.to_string(),
    }))
}

async fn get_tz_with_client_ip(
    InsecureClientIp(insecure_client_ip): InsecureClientIp,
    Extension(reader): Extension<Arc<Reader<Vec<u8>>>>,
) -> impl IntoResponse {
    // We use the insecure one to get X-Forwarded-For, etc
    get_tz(reader, insecure_client_ip)
}

async fn get_tz_with_explicit_ip(
    Extension(reader): Extension<Arc<Reader<Vec<u8>>>>,
    Path(ip): Path<IpAddr>,
) -> impl IntoResponse {
    get_tz(reader, ip)
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
    let cfg = Config::parse();
    let reader = Arc::new(Reader::open_readfile(cfg.db)?);
    let app = Router::new()
        .route("/", get(get_tz_with_client_ip))
        .route("/:ip", get(get_tz_with_explicit_ip))
        .layer(Extension(reader));
    let addr = SocketAddr::from((cfg.ip, cfg.port));
    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(wait_for_shutdown_request())
        .await?)
}
