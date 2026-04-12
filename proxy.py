import socket  # for creating network connections
import threading  # to handle each client in its own thread
import select  # to monitor multiple sockets at once (used in CONNECT tunneling)
import time  # for timing connections

from config import PROXY_PORT, SOCKET_TIMEOUT, BUFFER_SIZE  # proxy settings
from logger import logger  # for logging
from cache import cache  # the shared response cache
from filter import is_allowed, blocked_response  # host filtering


def parse_request(raw: bytes):
    try:
        if b"\r\n\r\n" in raw:
            header_block, _ = raw.split(b"\r\n\r\n", 1)  # split headers from body
        else:
            header_block = raw  # no body, just headers

        lines = header_block.decode("utf-8", errors="replace").split("\r\n")  # split into lines
        request_line = lines[0]  # first line is like "GET http://example.com HTTP/1.1"
        parts = request_line.split()
        if len(parts) < 3:
            return None  # malformed request line

        method, url, version = parts[0], parts[1], parts[2]  # extract method, URL, version

        headers = {}
        for line in lines[1:]:  # parse each header line
            if ":" in line:
                key, _, value = line.partition(":")  # split on first colon
                headers[key.strip().lower()] = value.strip()  # store lowercase key

        if method == "CONNECT":  # HTTPS tunnel request
            host_port = url
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)  # extract port from "host:port"
            else:
                host, port = host_port, 443  # default HTTPS port
            path = "/"
        else:
            if url.startswith("http://"):
                rest = url[7:]  # strip "http://"
            elif url.startswith("https://"):
                rest = url[8:]  # strip "https://"
            else:
                rest = url

            if "/" in rest:
                host_port, path = rest.split("/", 1)  # split host from path
                path = "/" + path
            else:
                host_port, path = rest, "/"  # no path, default to /

            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)  # extract port if present
            else:
                host = host_port
                port = 80  # default HTTP port

            if "host" in headers:  # use the Host header if available (more reliable)
                h = headers["host"]
                if ":" in h:
                    host, port_str = h.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host = h

        return {
            "method": method,
            "url": url,
            "version": version,
            "host": host,
            "port": port,
            "path": path,
            "headers": headers,
            "raw_headers": header_block,
        }
    except Exception as exc:
        logger.debug(f"parse_request error: {exc}")
        return None  # return None if anything goes wrong


def build_forwarded_request(parsed: dict, raw: bytes) -> bytes:
    method  = parsed["method"]
    path    = parsed["path"]
    version = parsed["version"]

    body = b""
    if b"\r\n\r\n" in raw:
        _, body = raw.split(b"\r\n\r\n", 1)  # extract the request body

    skip = {"proxy-connection", "proxy-authorization"}  # headers we don't forward
    header_lines = [f"{method} {path} {version}"]  # start with the request line
    for key, value in parsed["headers"].items():
        if key in skip:
            continue  # drop proxy-specific headers
        if key == "connection":
            header_lines.append("Connection: close")  # force connection close
        else:
            header_lines.append(f"{key.capitalize()}: {value}")  # forward the header

    if "connection" not in parsed["headers"]:
        header_lines.append("Connection: close")  # add Connection: close if missing

    head = "\r\n".join(header_lines) + "\r\n\r\n"  # join headers with CRLF
    return head.encode("utf-8") + body  # return full request as bytes


def recv_all(sock: socket.socket) -> bytes:
    data = b""
    sock.settimeout(SOCKET_TIMEOUT)  # set timeout so we don't wait forever
    try:
        while True:
            chunk = sock.recv(BUFFER_SIZE)  # read a chunk of data
            if not chunk:
                break  # connection closed
            data += chunk
    except socket.timeout:
        pass  # stop reading when no more data arrives
    return data


def parse_response_headers(response: bytes) -> dict:
    headers = {}
    try:
        if b"\r\n\r\n" in response:
            head, _ = response.split(b"\r\n\r\n", 1)  # isolate the header section
        else:
            head = response
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        for line in lines[1:]:  # skip the status line
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()  # store as lowercase key
    except Exception:
        pass
    return headers


def handle_connect(client_sock: socket.socket, parsed: dict,
                   client_addr: tuple) -> None:
    host = parsed["host"]
    port = parsed["port"]

    try:
        origin_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        origin_sock.settimeout(SOCKET_TIMEOUT)
        origin_sock.connect((host, port))  # connect to the destination server
    except Exception as exc:
        logger.error(f"CONNECT tunnel failed to {host}:{port} – {exc}")
        error_resp = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
        client_sock.sendall(error_resp)  # tell the client we couldn't connect
        return

    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")  # tell client tunnel is open
    logger.info(
        f"CONNECT tunnel {client_addr[0]}:{client_addr[1]} "
        f"<-> {host}:{port}"
    )

    sockets = [client_sock, origin_sock]
    client_sock.settimeout(None)  # remove timeout for the tunnel (it's bidirectional)
    origin_sock.settimeout(None)
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, SOCKET_TIMEOUT)  # wait for activity
            if exceptional:
                break  # error on a socket
            if not readable:
                break  # timed out with no data
            for s in readable:
                other = origin_sock if s is client_sock else client_sock  # figure out the other end
                try:
                    data = s.recv(BUFFER_SIZE)
                    if not data:
                        return  # connection closed
                    other.sendall(data)  # relay data to the other side
                except Exception:
                    return
    finally:
        origin_sock.close()  # always close the server-side socket


def handle_http(client_sock: socket.socket, parsed: dict,
                raw_request: bytes, client_addr: tuple) -> None:
    method = parsed["method"]
    host   = parsed["host"]
    port   = parsed["port"]
    url    = parsed["url"]

    cache_key = f"GET:{url}"  # cache key is method + URL
    if method == "GET":
        cached = cache.get(cache_key)  # check if we have a cached response
        if cached is not None:
            logger.info(
                f"CACHE HIT  {client_addr[0]}:{client_addr[1]} "
                f"GET {url}"
            )
            client_sock.sendall(cached)  # send cached response directly
            return

    forward_request = build_forwarded_request(parsed, raw_request)  # build the request to forward
    try:
        origin_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        origin_sock.settimeout(SOCKET_TIMEOUT)
        origin_sock.connect((host, port))  # connect to the origin server
        origin_sock.sendall(forward_request)  # send the request
        response = recv_all(origin_sock)  # read the full response
        origin_sock.close()
    except Exception as exc:
        logger.error(
            f"Origin connection failed {host}:{port} for "
            f"{client_addr[0]}:{client_addr[1]} – {exc}"
        )
        error_resp = (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n"
            b"Proxy error: could not reach origin server.\r\n"
        )
        client_sock.sendall(error_resp)  # tell the client the origin failed
        return

    if response:
        try:
            client_sock.sendall(response)  # forward the response to the client
        except Exception as exc:
            logger.warning(f"Failed to send response to client – {exc}")

    if method == "GET" and response:
        resp_headers = parse_response_headers(response)  # parse headers for caching
        if response.startswith(b"HTTP/") and b"200" in response[:20]:  # only cache 200 OK
            cache.put(cache_key, response, resp_headers)
            logger.debug(f"CACHE STORE {url}")

    logger.info(
        f"HTTP {method} {client_addr[0]}:{client_addr[1]} "
        f"-> {host}:{port} {url} "
        f"| response={len(response)}B"
    )


def handle_client(client_sock: socket.socket, client_addr: tuple) -> None:
    start_time = time.time()  # track how long the connection takes
    try:
        client_sock.settimeout(SOCKET_TIMEOUT)
        raw_request = b""
        while b"\r\n\r\n" not in raw_request:  # keep reading until we have full headers
            chunk = client_sock.recv(BUFFER_SIZE)
            if not chunk:
                break  # client disconnected
            raw_request += chunk
            if len(raw_request) > 1_048_576:
                break  # stop if request is larger than 1MB

        if not raw_request:
            return  # nothing received

        parsed = parse_request(raw_request)  # parse the HTTP request
        if parsed is None:
            logger.warning(f"Malformed request from {client_addr[0]}:{client_addr[1]}")
            return

        host   = parsed["host"]
        method = parsed["method"]
        url    = parsed["url"]

        logger.info(
            f"REQUEST {client_addr[0]}:{client_addr[1]} "
            f"{method} {url} -> {host}:{parsed['port']}"
        )

        if not is_allowed(host):  # check blacklist/whitelist
            client_sock.sendall(blocked_response(host))  # send 403 if blocked
            logger.info(
                f"BLOCKED {client_addr[0]}:{client_addr[1]} "
                f"{method} {url}"
            )
            return

        if method == "CONNECT":
            handle_connect(client_sock, parsed, client_addr)  # HTTPS tunnel
        else:
            handle_http(client_sock, parsed, raw_request, client_addr)  # regular HTTP

    except socket.timeout:
        logger.debug(f"Client timeout: {client_addr[0]}:{client_addr[1]}")
    except Exception as exc:
        logger.error(f"handle_client error ({client_addr}): {exc}")
    finally:
        elapsed = time.time() - start_time  # compute how long this connection lasted
        logger.debug(
            f"Connection closed {client_addr[0]}:{client_addr[1]} "
            f"({elapsed:.3f}s)"
        )
        try:
            client_sock.close()  # always close the client socket
        except Exception:
            pass


def start_proxy(port: int = PROXY_PORT) -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow reuse of the port
    server_sock.bind(("0.0.0.0", port))  # listen on all interfaces
    server_sock.listen(50)  # allow up to 50 queued connections

    logger.info(f"Proxy server started on port {port}")
    logger.info(f"Configure your browser/client to use 127.0.0.1:{port} as HTTP proxy")

    try:
        while True:
            client_sock, client_addr = server_sock.accept()  # wait for a new client
            thread = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr),
                daemon=True,  # thread dies when main program exits
            )
            thread.start()  # handle client in a new thread
            logger.debug(
                f"New connection from {client_addr[0]}:{client_addr[1]} "
                f"(active threads: {threading.active_count()})"
            )
    except KeyboardInterrupt:
        logger.info("Proxy server shutting down.")
    finally:
        server_sock.close()  # close the server socket on exit


if __name__ == "__main__":
    start_proxy()  # run the proxy when script is executed directly
