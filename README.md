# CSC 430 – Caching Proxy Server

A multi-threaded HTTP caching proxy server written in Python.

## File Structure

| File | Description |
|---|---|
| `proxy.py` | Main server – socket setup, threading, request dispatch |
| `cache.py` | In-memory response cache with TTL-based invalidation |
| `filter.py` | Blacklist / whitelist filtering |
| `logger.py` | Structured logging to console and `proxy.log` |
| `config.py` | All tunable constants (port, timeouts, TTL, …) |
| `blacklist.txt` | Domains/IPs to block (one per line) |
| `whitelist.txt` | Domains/IPs to allow (used when `WHITELIST_MODE=True`) |

## Requirements

- Python 3.9+
- No third-party packages – only the standard library is used.

## Running the Proxy

```bash
python proxy.py
```

The server listens on port **8888** by default (change `PROXY_PORT` in `config.py`).

## Configuring Your Browser

Set your browser's HTTP proxy to:

- **Host:** `127.0.0.1`
- **Port:** `8888`

Or use `curl`:

```bash
curl -x http://127.0.0.1:8888 http://example.com
```

## Configuration (`config.py`)

| Setting | Default | Description |
|---|---|---|
| `PROXY_PORT` | `8888` | Port the proxy listens on |
| `SOCKET_TIMEOUT` | `10` | Seconds before a socket times out |
| `DEFAULT_CACHE_TTL` | `300` | Fallback cache lifetime in seconds |
| `MAX_CACHE_ENTRIES` | `200` | Maximum number of cached responses |
| `WHITELIST_MODE` | `False` | If `True`, only whitelisted hosts are allowed |
| `LOG_FILE` | `proxy.log` | Path to the log file |
| `BUFFER_SIZE` | `4096` | Socket read buffer size |

## Blacklist / Whitelist

- Add one domain or IP per line to `blacklist.txt` to block those hosts.
- Blocked requests receive a **403 Forbidden** HTML response.
- Set `WHITELIST_MODE = True` in `config.py` and populate `whitelist.txt` to switch to allow-list mode.

## Features

- **A. Basic Proxy** – forwards HTTP GET/POST/etc. to origin; relays response to client  
- **B. Socket Programming** – raw TCP sockets, configurable listen port  
- **C. Request Parsing** – extracts method, host, port, path; rewrites request line; strips proxy headers  
- **D. Threading** – one daemon thread per client connection  
- **E. Logging** – client IP/port, target host/port, method, URL, timestamp, errors  
- **F. Content Caching** – in-memory cache; TTL from `Cache-Control`/`Expires` or default; LRU-style eviction at capacity  
- **G. Blacklist/Whitelist** – domain/IP filtering with custom 403 response  
- **HTTPS CONNECT tunnel** – raw TCP relay for HTTPS without decryption  
