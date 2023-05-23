# tzserver | [![Tests](https://img.shields.io/github/actions/workflow/status/cdown/tzserver/ci.yml?branch=master)](https://github.com/cdown/tzserver/actions?query=branch%3Amaster)

tzserver is a fast GeoIP lookup service in Rust, using the
[Axum](https://docs.rs/axum/latest/axum/) web framework. It provides one
possible server for [tzupdate](https://github.com/cdown/tzupdate).

## Usage

Download GeoLite2-City.mmdb from
[here](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/), and
extract it.

By default, the server runs on TCP 0.0.0.0:3000. You can change this with the
`--ip` and `--port` options. You can also set the GeoIP database file location
with the `--db` option.

You can then query `/` to get data for the connecting IP (respecting things
like X-Real-IP, X-Forwarded-For, and the like), or `/8.8.8.8` to get details
for (for example) 8.8.8.8.

## Rate limiting

tzserver is designed to be run behind a local reverse proxy, so rate limiting
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
