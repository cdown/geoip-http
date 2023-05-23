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

With the performance offered, rate limiting isn't really a major consideration.
If it becomes necessary in future, it can be added via
[tower-governor](https://github.com/benwis/tower-governor).

## Performance

On my T14s Gen 2:

    % wrk -t"$(nproc)" -c 400 -d30s http://127.0.0.1:3000/8.8.8.8
    Running 30s test @ http://127.0.0.1:3000/8.8.8.8
      8 threads and 400 connections
      Thread Stats   Avg      Stdev     Max   +/- Stdev
        Latency     1.51ms    1.32ms  32.44ms   85.73%
        Req/Sec    37.51k    10.13k   63.36k    67.73%
      8962612 requests in 30.07s, 1.26GB read
    Requests/sec: 298093.53
    Transfer/sec:     42.93MB
