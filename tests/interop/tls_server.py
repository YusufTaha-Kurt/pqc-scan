"""Minimal TLS server for interoperability tests (run inside a container).

    python tls_server.py CERT KEY PORT

It uses the container's OpenSSL defaults. With OpenSSL 3.5 or newer these
include the hybrid group X25519MLKEM768, which is what the interop test
checks. Standard library only.
"""

import socket
import ssl
import sys
import threading


def main() -> None:
    cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    print(ssl.OPENSSL_VERSION, flush=True)
    with socket.create_server(("0.0.0.0", port)) as server:  # noqa: S104 - container only
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handshake, args=(context, conn), daemon=True).start()


def handshake(context: ssl.SSLContext, conn: socket.socket) -> None:
    conn.settimeout(5)
    try:
        with context.wrap_socket(conn, server_side=True):
            pass
    except (OSError, ssl.SSLError):
        conn.close()


if __name__ == "__main__":
    main()
