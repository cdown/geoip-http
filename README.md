# geoip-http | [![Tests](https://img.shields.io/github/actions/workflow/status/cdown/geoip-http/ci.yml?branch=master)](https://github.com/cdown/geoip-http/actions?query=branch%3Amaster)

geoip-http is a fast GeoIP lookup service in Rust, using the
[Axum](https://docs.rs/axum/latest/axum/) web framework. It provides one
possible server for [tzupdate](https://github.com/cdown/tzupdate).

## Features

- Fast, uses Axum web framework
- Simple, less than 300 lines of code
- Safe hot reload of GeoIP DB without restarting
- Correct cache behaviour for implicit/explicit IP lookup
- Direct dump of GeoIP data: no filtering
- Support for both explicit and implicit (client IP) queries
- Support for X-Forwarded-For, X-Real-IP, CloudFront, etc
- Sequence based logging for debugging

## Usage

Download GeoLite2-City.mmdb from
[here](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/), and
extract it.

By default, the server runs on TCP 0.0.0.0:3000. You can change this with the
`--ip` and `--port` options. You can also set the GeoIP database file location
with the `--db` option.

You can then query `/` to get data for the connecting IP (respecting things
like X-Real-IP, X-Forwarded-For, and the like), or `/8.8.8.8` to get details
for (for example) 8.8.8.8:

```
% curl --silent http://127.0.0.1:3000/8.8.8.8 | jq '.location'
{
  "accuracy_radius": 5,
  "latitude": 34.0544,
  "longitude": -118.2441,
  "metro_code": 803,
  "time_zone": "America/Los_Angeles"
}
```

The format matches that of the maxminddb crate's [City
struct](https://docs.rs/maxminddb/latest/maxminddb/geoip2/struct.City.html),
represented as JSON by its `Serialize` trait.

## Logging

To see debug info, run with `RUST_LOG=geoip_http=debug,tower_http=debug`.

## Rate limiting

geoip-http is designed to be run behind a local reverse proxy, so rate limiting
generally should happen there. It can also be added via
[tower-governor](https://github.com/benwis/tower-governor).

## Performance

On my T14s Gen 2:

    % wrk -t"$(nproc)" -c400 -d30s http://127.0.0.1:3000/8.8.8.8
    Running 30s test @ http://127.0.0.1:3000/8.8.8.8
      8 threads and 400 connections
      Thread Stats   Avg      Stdev     Max   +/- Stdev
        Latency     1.28ms    1.11ms  29.11ms   87.45%
        Req/Sec    42.99k    10.07k  158.55k    75.56%
      10269395 requests in 30.09s, 1.44GB read
    Requests/sec: 341246.16
    Transfer/sec:     49.14MB

## Example server config

### Nginx proxy config

Fill in `ssl_certificate` and `ssl_certificate_key`.

```
http {
    limit_conn_zone $binary_remote_addr zone=geoip_conn_limit:2m;
    limit_req_zone $binary_remote_addr zone=geoip_rate_limit:2m rate=100r/m;

    upstream geoip-backend {
        server 127.0.0.1:3000;
        keepalive 16;
    }

    server {
        listen 80;
        listen [::]:80;
        server_name geoip.chrisdown.name;

        client_body_timeout 2s;
        client_header_timeout 2s;

        location / {
            limit_req zone=geoip_rate_limit;
            limit_conn addr 5;
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name geoip.chrisdown.name;

        client_body_timeout 2s;
        client_header_timeout 2s;

        ssl_certificate ...;
        ssl_certificate_key ...;

        location / {
            limit_req zone=geoip_rate_limit;
            limit_conn addr 50;
            proxy_pass http://geoip-backend;
        }
    }
}
```

### Systemd unit for geoip-http

Fill in `--db`.

```
[Service]
ExecStart=/usr/bin/geoip-http --db ...
ExecReload=/usr/bin/curl -v http://127.0.0.1:3000/reload/geoip
Restart=always
```

## Attribution

This product is designed to use GeoLite2 data created by MaxMind, available
from https://maxmind.com.
