PROXY_PORT = 8888          # port the proxy listens on
SOCKET_TIMEOUT = 10        # seconds before a socket times out
DEFAULT_CACHE_TTL = 300    # default cache lifetime in seconds (5 min)
MAX_CACHE_ENTRIES = 200    # max number of responses to keep in cache
BLACKLIST_FILE = "blacklist.txt"  # file with blocked domains
WHITELIST_FILE = "whitelist.txt"  # file with allowed domains
WHITELIST_MODE = False     # if True, only whitelist hosts are allowed
LOG_FILE = "proxy.log"     # file where logs are written
BUFFER_SIZE = 4096         # how many bytes to read at once from a socket

# --- Bonus H: HTTPS MITM settings ---
MITM_ENABLED = True        # set to True to intercept HTTPS traffic (MITM mode)
CA_CERT_FILE = "ca_cert.pem"  # CA certificate file used to sign fake certs
CA_KEY_FILE = "ca_key.pem"    # CA private key file

# --- Bonus I: Admin Interface settings ---
ADMIN_ENABLED = True       # set to True to start the web admin dashboard
ADMIN_PORT = 8889          # port the admin interface listens on
