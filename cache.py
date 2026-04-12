import time  # for tracking expiry times
import threading  # to make cache access thread-safe
from email.utils import parsedate_to_datetime  # parses HTTP date strings
from typing import Optional  # for optional return types
from config import DEFAULT_CACHE_TTL, MAX_CACHE_ENTRIES  # cache settings
from logger import logger  # for logging cache events


class CacheEntry:
    def __init__(self, response: bytes, ttl: float):
        self.response = response  # the raw HTTP response to cache
        self.expires_at = time.time() + ttl  # when this entry becomes stale


class Cache:
    def __init__(self):
        self._store: dict[str, CacheEntry] = {}  # key -> cached entry
        self._lock = threading.Lock()  # prevents race conditions across threads

    def get(self, key: str) -> Optional[bytes]:
        with self._lock:  # lock so only one thread accesses at a time
            entry = self._store.get(key)  # look up the key
            if entry is None:
                return None  # not in cache
            if time.time() > entry.expires_at:  # check if it's expired
                del self._store[key]  # remove the stale entry
                logger.debug(f"Cache EXPIRED: {key}")
                return None
            logger.info(f"Cache HIT: {key}")
            return entry.response  # return the cached response

    def put(self, key: str, response: bytes, headers: dict) -> None:
        ttl = self._ttl_from_headers(headers)  # figure out how long to cache
        if ttl is None:
            logger.debug(f"Cache SKIP (no-store/no-cache): {key}")
            return  # don't cache if the server said not to

        with self._lock:
            if len(self._store) >= MAX_CACHE_ENTRIES:  # if cache is full
                oldest_key = min(self._store, key=lambda k: self._store[k].expires_at)  # find oldest entry
                del self._store[oldest_key]  # evict it to make room
                logger.debug(f"Cache EVICT (capacity): {oldest_key}")

            self._store[key] = CacheEntry(response, ttl)  # store the new entry
            logger.debug(f"Cache STORE (ttl={ttl:.0f}s): {key}")

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)  # remove entry if it exists

    def size(self) -> int:
        with self._lock:
            return len(self._store)  # return number of cached entries

    @staticmethod
    def _ttl_from_headers(headers: dict) -> Optional[float]:
        cache_control = headers.get("cache-control", "")  # read Cache-Control header

        if "no-store" in cache_control or "no-cache" in cache_control:
            return None  # server says don't cache this

        for part in cache_control.split(","):  # look for max-age directive
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    return float(part.split("=", 1)[1])  # use max-age as TTL
                except ValueError:
                    pass

        expires_header = headers.get("expires", "")  # fallback: check Expires header
        if expires_header:
            try:
                expires_dt = parsedate_to_datetime(expires_header)  # parse the date
                ttl = expires_dt.timestamp() - time.time()  # compute seconds until expiry
                if ttl > 0:
                    return ttl  # use it if it's in the future
            except Exception:
                pass

        return DEFAULT_CACHE_TTL  # fallback to default TTL if nothing else worked


cache = Cache()  # global cache instance shared across all threads
