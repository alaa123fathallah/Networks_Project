import os  # for checking if files exist
from config import BLACKLIST_FILE, WHITELIST_FILE, WHITELIST_MODE  # load config settings
from logger import logger  # for logging blocked requests


def _load_list(filepath: str) -> set:
    entries: set = set()  # start with an empty set
    if not os.path.exists(filepath):  # if the file doesn't exist, return empty set
        return entries
    with open(filepath, "r", encoding="utf-8") as f:  # open the file for reading
        for line in f:  # go through each line
            line = line.strip()  # remove whitespace/newlines
            if line and not line.startswith("#"):  # skip empty lines and comments
                entries.add(line.lower())  # add the entry in lowercase
    return entries  # return the set of entries


def is_allowed(host: str) -> bool:
    host = host.lower().split(":")[0]  # lowercase and strip port number
    normalised = host.removeprefix("www.")  # also check without "www."

    blacklist = _load_list(BLACKLIST_FILE)  # load the blacklist from file
    whitelist = _load_list(WHITELIST_FILE)  # load the whitelist from file

    if WHITELIST_MODE:  # if whitelist mode is on, only allow listed hosts
        allowed = (host in whitelist) or (normalised in whitelist)  # check both forms
        if not allowed:
            logger.info(f"FILTER BLOCK (not whitelisted): {host}")  # log the block
        return allowed

    blocked = (host in blacklist) or (normalised in blacklist)  # check if host is blocked
    if blocked:
        logger.info(f"FILTER BLOCK (blacklisted): {host}")  # log the block
    return not blocked  # allow if not blocked


def blocked_response(host: str) -> bytes:
    body = (
        f"<html><body>"
        f"<h1>403 Forbidden</h1>"
        f"<p>Access to <strong>{host}</strong> has been blocked by the proxy.</p>"  # show blocked host
        f"</body></html>"
    )
    body_bytes = body.encode("utf-8")  # encode HTML to bytes
    response = (
        f"HTTP/1.1 403 Forbidden\r\n"  # HTTP status line
        f"Content-Type: text/html; charset=utf-8\r\n"  # tell the browser it's HTML
        f"Content-Length: {len(body_bytes)}\r\n"  # size of the body
        f"Connection: close\r\n"  # close connection after response
        f"\r\n"  # blank line separating headers from body
    ).encode("utf-8") + body_bytes  # combine headers and body as bytes
    return response
