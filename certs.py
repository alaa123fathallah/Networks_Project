import os       # for file path checks
import ssl      # for wrapping sockets with TLS
import tempfile # for temporary cert files
import subprocess  # to call openssl commands

from config import CA_CERT_FILE, CA_KEY_FILE  # paths for the CA certificate and key
from logger import logger  # for logging cert events

# ---------------------------------------------------------------------------
# Bonus H – HTTPS MITM Certificate Generation
# This module generates a self-signed CA and per-domain certificates so the
# proxy can decrypt HTTPS traffic for inspection (educational / debugging).
# ---------------------------------------------------------------------------


def generate_ca():
    """Create a self-signed CA key + certificate if they don't already exist."""
    if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):  # already generated
        logger.info("CA certificate already exists, skipping generation")
        return

    logger.info("Generating self-signed CA certificate …")

    # generate a 2048-bit RSA private key for the CA
    subprocess.run(
        ["openssl", "genrsa", "-out", CA_KEY_FILE, "2048"],
        check=True, capture_output=True,
    )

    # create a self-signed certificate valid for 3 years
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", CA_KEY_FILE,
            "-out", CA_CERT_FILE,
            "-days", "1095",
            "-subj", "/CN=ProxyCA/O=CSC430 Proxy/C=LB",  # certificate subject fields
        ],
        check=True, capture_output=True,
    )
    logger.info(f"CA certificate saved to {CA_CERT_FILE}")


def generate_host_cert(hostname: str) -> tuple:
    """Generate a TLS certificate for *hostname* signed by our CA.

    Returns (cert_path, key_path) as temporary files.
    """
    # create a temporary key file for this host
    key_fd, key_path = tempfile.mkstemp(suffix=".key")
    os.close(key_fd)  # close the file descriptor, openssl will write to the path

    # create a temporary cert file for this host
    cert_fd, cert_path = tempfile.mkstemp(suffix=".crt")
    os.close(cert_fd)

    # create a temporary CSR (certificate signing request) file
    csr_fd, csr_path = tempfile.mkstemp(suffix=".csr")
    os.close(csr_fd)

    try:
        # step 1: generate a private key for the host
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            check=True, capture_output=True,
        )

        # step 2: create a CSR with the hostname as the Common Name
        subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", key_path,
                "-out", csr_path,
                "-subj", f"/CN={hostname}",  # set CN to the target hostname
            ],
            check=True, capture_output=True,
        )

        # step 3: sign the CSR with our CA to produce a valid certificate
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", csr_path,
                "-CA", CA_CERT_FILE,
                "-CAkey", CA_KEY_FILE,
                "-CAcreateserial",
                "-out", cert_path,
                "-days", "365",  # valid for 1 year
            ],
            check=True, capture_output=True,
        )

        logger.debug(f"Generated MITM cert for {hostname}")
    finally:
        if os.path.exists(csr_path):
            os.remove(csr_path)  # clean up the CSR, we don't need it anymore

    return cert_path, key_path  # return paths so the caller can load them


def create_mitm_ssl_context(hostname: str) -> ssl.SSLContext:
    """Build an SSL context that presents a cert for *hostname* to the client."""
    cert_path, key_path = generate_host_cert(hostname)  # generate cert on the fly

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # server-side context
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)  # load the generated cert
    context.check_hostname = False  # we are the proxy, not validating our own cert
    context.verify_mode = ssl.CERT_NONE  # don't ask the client for a cert

    # clean up temp files after loading into the context
    os.remove(cert_path)
    os.remove(key_path)

    return context  # ready to wrap the client socket
